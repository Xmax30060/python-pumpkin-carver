#!/usr/init/env python3
# -*- coding: utf-8 -*-
"""Récupération/carving prudent depuis une image disque existante (.img/.dd/.raw)
étendu aux formats vidéo (MP4, MKV, AVI, MOV) et images/documents.

- Source ouverte STRICTEMENT en lecture seule ; ne modifie jamais l'image.
- Scan parallèle des signatures par blocs, avec recouvrement.
- Analyse approfondie pour les vidéos > 500 Mo (détection d'anomalies).
- Correction automatique enregistrée directement dans le dossier principal.
- SHA-256 de chaque fichier extrait pour la chaîne de custody et déduplication.
- Reprise sur interruption avec --resume.
- Journalisation structurée, manifeste JSONL et rapport HTML.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import logging
import os
import subprocess
import struct
import sys
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # Pillow is optional for image validation.
    Image = None
from typing import Optional

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #

MIB = 1024 * 1024
GIB = 1024 * MIB

SIGNATURES: tuple[tuple[str, bytes], ...] = (
    # Images & Documents
    ("jpg", b"\xff\xd8\xff"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("pdf", b"%PDF-"),
    ("gif", b"GIF87a"),
    ("gif", b"GIF89a"),
    ("bmp", b"BM"),
    # Vidéos
    ("mkv", b"\x1a\x45\xdf\xa3"),  # Matroska / WebM EBML header
    ("mp4", b"ftypis0"),
    ("mp4", b"ftypisom"),
    ("mp4", b"ftypmp42"),
    ("mp4", b"ftypdash"),
    ("mp4", b"ftypMSNV"),
    ("mp4", b"ftypavc1"),
    ("mov", b"ftypqt  "),          # QuickTime / MOV
    ("avi", b"RIFF"),             # AVI
)

MAX_SIZES = {
    "jpg": 256 * MIB, "png": 512 * MIB, "pdf": 512 * MIB, "gif": 128 * MIB, "bmp": 256 * MIB,
    "mp4": 2 * GIB, "mkv": 2 * GIB, "mov": 2 * GIB, "avi": 2 * GIB
}

OVERLAP = max(len(sig) for _, sig in SIGNATURES) - 1
HASH_CHUNK = 8 * MIB
WRITE_CHUNK = 8 * MIB
MANIFEST_SCHEMA_VERSION = 7

log = logging.getLogger("recup_after")


# --------------------------------------------------------------------------- #
# Erreurs dédiées
# --------------------------------------------------------------------------- #

class RecupError(Exception):
    """Erreur attendue, destinée à être affichée proprement à l'utilisateur."""


# --------------------------------------------------------------------------- #
# Scan des signatures (multi-processus)
# --------------------------------------------------------------------------- #

# pylint: disable=too-many-locals,too-many-nested-blocks
def scan_range(job: tuple[str, int, int, int]) -> list[tuple[int, str]]:
    """Scan one image range for known file signatures."""
    path, start, stop, chunk_size = job
    found: list[tuple[int, str]] = []
    try:
        with open(path, "rb", buffering=0) as f:
            f.seek(start)
            carry = b""
            pos = start
            while pos < stop:
                block = f.read(min(chunk_size, stop - pos))
                if not block:
                    break
                data = carry + block
                base = pos - len(carry)
                for ext, sig in SIGNATURES:
                    i = 0
                    while True:
                        i = data.find(sig, i)
                        if i < 0:
                            break
                        absolute = base + i
                        if start <= absolute < stop:
                            if ext == "avi":
                                f.seek(absolute + 8)
                                sub = f.read(4)
                                if sub != b"AVI ":
                                    i += 1
                                    continue
                            real_offset = absolute
                            if ext in ("mp4", "mov") and absolute >= 4:
                                f.seek(absolute - 4)
                                size_bytes = f.read(4)
                                box_len = struct.unpack(">I", size_bytes)[0]
                                if 8 <= box_len <= 100:
                                    real_offset = absolute - 4

                            found.append((real_offset, ext))
                        i += 1
                carry = data[-OVERLAP:] if OVERLAP else b""
                pos += len(block)
    except OSError as e:
        raise RecupError(f"Échec de lecture du bloc [{start}:{stop}] : {e}") from e
    return found


def scan_signatures(
    path: Path, workers: int, chunk_size: int, progress_cb=None
) -> tuple[list[tuple[int, str]], int]:
    """Scan an image in parallel and return unique signature offsets and size."""
    size = path.stat().st_size
    if size == 0:
        return [], 0
    jobs = [
        (str(path), start, min(size, start + chunk_size), chunk_size)
        for start in range(0, size, chunk_size)
    ]
    found: list[tuple[int, str]] = []
    done = 0
    total = len(jobs)
    log.info("Image : %s (%.2f Gio)", path, size / GIB)
    log.info("Scan : %d processus, blocs de %.0f Mio, %d tâches", workers, chunk_size / MIB, total)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_range, j) for j in jobs]
        try:
            for fut in as_completed(futures):
                found.extend(fut.result())
                done += 1
                if progress_cb and (done == total or done % max(1, total // 100) == 0):
                    progress_cb(done, total)
        except RecupError:
            for fut in futures:
                fut.cancel()
            raise
    return sorted(set(found)), size


# --------------------------------------------------------------------------- #
# Parsers de longueur par format
# --------------------------------------------------------------------------- #

def find_marker(f, offset: int, limit: int, marker: bytes, start_after: int = 0) -> Optional[int]:
    """Find a byte marker in a bounded region and return its relative end offset."""
    f.seek(offset + start_after)
    cursor = offset + start_after
    carry = b""
    while cursor < limit:
        block = f.read(min(4 * MIB, limit - cursor))
        if not block:
            return None
        data = carry + block
        idx = data.find(marker)
        if idx >= 0:
            return cursor - len(carry) + idx + len(marker) - offset
        carry = data[-max(1, len(marker) - 1):]
        cursor += len(block)
    return None


def png_length(f, offset: int, image_size: int) -> Optional[int]:
    """Determine a PNG file length by parsing chunks through IEND."""
    f.seek(offset)
    if f.read(8) != b"\x89PNG\r\n\x1a\n":
        return None
    cur = offset + 8
    limit = min(image_size, offset + MAX_SIZES["png"])
    while cur + 12 <= limit:
        f.seek(cur)
        h = f.read(8)
        if len(h) != 8:
            return None
        n = struct.unpack(">I", h[:4])[0]
        typ = h[4:]
        if n > MAX_SIZES["png"] or cur + 12 + n > limit:
            return None
        cur += 12 + n
        if typ == b"IEND":
            return cur - offset if n == 0 else None
    return None


def gif_length(f, offset: int, image_size: int) -> Optional[int]:
    """Determine a GIF file length by locating its trailer marker."""
    f.seek(offset)
    if f.read(6) not in (b"GIF87a", b"GIF89a"):
        return None
    n = find_marker(f, offset, min(image_size, offset + MAX_SIZES["gif"]), b"\x3b", 6)
    return n if n is not None and n >= 14 else None


def bmp_length(f, offset: int, image_size: int) -> Optional[int]:
    """Read the declared BMP length and validate it against bounds."""
    f.seek(offset)
    h = f.read(54)
    if len(h) < 26 or h[:2] != b"BM":
        return None
    size = struct.unpack_from("<I", h, 2)[0]
    return size if size <= min(image_size - offset, MAX_SIZES["bmp"]) else None


def pdf_length(f, offset: int, image_size: int) -> Optional[int]:
    """Determine a PDF length from its last EOF marker within the size limit."""
    limit = min(image_size, offset + MAX_SIZES["pdf"])
    f.seek(offset)
    if f.read(5) != b"%PDF-":
        return None
    cur = offset + 5
    tail = b""
    last = None
    while cur < limit:
        b = f.read(min(4 * MIB, limit - cur))
        if not b:
            break
        data = tail + b
        p = 0
        while True:
            i = data.find(b"%%EOF", p)
            if i < 0:
                break
            candidate = cur - len(tail) + i + 5 - offset
            if candidate >= 16:
                last = candidate
            p = i + 5
        tail = data[-4:]
        cur += len(b)
    return last


def video_length(
    _f, offset: int, image_size: int, ext: str,
    next_offset: Optional[int] = None,
) -> int:
    """Estimate a video extent using the next signature and format limit."""
    max_limit = MAX_SIZES.get(ext, 100 * MIB)
    available = image_size - offset
    if next_offset is not None and next_offset > offset:
        distance = next_offset - offset
        if distance <= max_limit:
            return distance
    return min(available, max_limit)


# --------------------------------------------------------------------------- #
# Analyse et Correction Vidéo via FFprobe / FFmpeg
# --------------------------------------------------------------------------- #

def image_validate(path: Path, ext: str) -> dict:
    """Validate a recovered image and return its basic metadata."""
    if ext in ("mp4", "mkv", "mov", "avi"):
        return {
            "validation": "not_applicable", "width": None, "height": None,
            "exif_date": None, "error": None,
        }
    if Image is None:
        return {
            "validation": "pillow_missing",
            "width": None,
            "height": None,
            "exif_date": None,
            "error": "Pillow absent",
        }
    try:
        with Image.open(path) as im:
            fmt = im.format
            width, height = im.size
            im.verify()
        return {
            "validation": "valid", "width": width, "height": height,
            "format": fmt, "exif_date": None, "error": None,
        }
    except (OSError, ValueError, SyntaxError) as exc:
        return {
            "validation": "invalid",
            "width": None,
            "height": None,
            "exif_date": None,
            "error": str(exc)[:300],
        }


def analyze_large_video(path: Path, size_bytes: int) -> dict:
    """Use ffprobe to inspect large videos and flag likely anomalies."""
    result = {
        "video_analysis": "not_checked",
        "duration_sec": None,
        "bitrate_kbps": None,
        "anomaly": False,
        "anomaly_reason": None
    }

    if size_bytes <= 500 * MIB:
        return result

    ffprobe_path = shutil.which("ffprobe")
    if not ffprobe_path:
        result["video_analysis"] = "ffprobe_missing"
        return result

    try:
        cmd = [
            ffprobe_path,
            "-v", "error",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            str(path)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if proc.returncode != 0:
            result["video_analysis"] = "corrupt_or_invalid_container"
            result["anomaly"] = True
            result["anomaly_reason"] = f"Erreur ffprobe: {proc.stderr.strip()[:200]}"
            return result

        data = json.loads(proc.stdout)
        fmt_info = data.get("format", {})
        duration = float(fmt_info.get("duration", 0))

        if duration > 0:
            calculated_bitrate = (size_bytes * 8) / duration / 1000
            result["bitrate_kbps"] = int(calculated_bitrate)
            result["duration_sec"] = duration
            result["video_analysis"] = "analyzed"

            if size_bytes > 500 * MIB and duration < 30 and calculated_bitrate > 30000:
                result["anomaly"] = True
                result["anomaly_reason"] = (
                    f"Débit excessif ({int(calculated_bitrate)} kbps) "
                    f"pour une courte durée ({duration:.2f}s) et une taille de "
                    f"{size_bytes / MIB:.2f} Mo."
                )
        else:
            result["anomaly"] = True
            result["anomaly_reason"] = "Durée nulle ou illisible."

    except (
        OSError, ValueError, TypeError, json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        result["video_analysis"] = "analysis_failed"
        result["anomaly"] = True
        result["anomaly_reason"] = str(exc)[:200]

    return result


def correct_video_with_ffmpeg(
    input_path: Path, output_dir: Path, ext: str,
) -> Optional[tuple[Path, str]]:
    """Corrige une vidéo anormale et enregistre le résultat dans le dossier principal."""
    ffmpeg_path = shutil.which("ffmpeg")
    if not ffmpeg_path:
        log.warning("FFmpeg introuvable : impossible d'effectuer la correction automatique.")
        return None

    # Enregistrement direct dans le dossier principal output_dir (pas de sous-dossier)
    corrected_filename = f"{input_path.stem}_corrige.{ext}"
    corrected_path = output_dir / corrected_filename

    try:
        cmd = [
            ffmpeg_path, "-y",
            "-i", str(input_path),
            "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
            "-c:a", "libvo_aacenc",
            str(corrected_path)
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        if proc.returncode == 0 and corrected_path.exists() and corrected_path.stat().st_size > 0:
            h = hashlib.sha256()
            with open(corrected_path, "rb", buffering=0) as f:
                while True:
                    block = f.read(HASH_CHUNK)
                    if not block:
                        break
                    h.update(block)
            return corrected_path, h.hexdigest()
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning(
            "Échec de la correction FFmpeg pour %s : %s",
            input_path.name,
            exc,
        )

    return None


@dataclass
class RunStats:
    """Counters and per-format totals for a carving run."""
    extracted: int = 0
    rejected: int = 0
    duplicates: int = 0
    anomalies: int = 0
    corrected: int = 0
    counts: dict = field(default_factory=dict)


def load_existing_manifest(manifest_path: Path) -> tuple[list[dict], set[int], set[str]]:
    """Load prior manifest records and collect covered offsets and hashes."""
    records: list[dict] = []
    seen_hashes: set[str] = set()
    covered_starts: set[int] = set()
    if not manifest_path.exists():
        return records, covered_starts, seen_hashes
    with open(manifest_path, "r", encoding="utf-8") as mf:
        for line in mf:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(rec)
            covered_starts.add(rec["offset_decimal"])
            if rec.get("sha256"):
                seen_hashes.add(rec["sha256"])
    return records, covered_starts, seen_hashes


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    p = argparse.ArgumentParser(
        description="Carving prudent d'images et vidéos depuis un .img/.dd."
    )
    p.add_argument("image", type=Path, help="Fichier image disque source")
    p.add_argument("-o", "--output", type=Path, default=None)
    p.add_argument("-j", "--workers", type=int, default=max(1, min(12, os.cpu_count() or 1)))
    p.add_argument("--chunk-mib", type=int, default=64)
    p.add_argument(
        "--min-size", type=int, default=1024,
        help="Taille minimale d'un fichier extrait (octets)",
    )
    p.add_argument("--max-files", type=int, default=0, help="Limite d'extractions (0=illimité)")
    p.add_argument("--no-dedup", action="store_true", help="Ne pas dédupliquer par hash SHA-256")
    p.add_argument("--resume", action="store_true", help="Reprendre un run existant")
    p.add_argument("--dry-run", action="store_true", help="Estimation rapide sans extraction")
    p.add_argument("--formats", type=str, default="jpg,png,gif,bmp,pdf,mp4,mkv,mov,avi",
                    help="Formats à rechercher séparés par des virgules")
    p.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    p.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux")
    return p


def configure_logging(dest: Optional[Path], verbose: bool, quiet: bool) -> None:
    """Configure console and optional file logging."""
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console)

    if dest is not None:
        dest.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(dest / "recup_after.log", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(file_handler)


def hash_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a file in chunks."""
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            block = f.read(HASH_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# pylint: disable=too-many-locals,too-many-branches,too-many-statements,consider-using-with
def main() -> int:
    """Run the carving workflow and write recovery reports."""
    parser = build_arg_parser()
    args = parser.parse_args()

    src = args.image.expanduser().resolve()
    if not src.is_file():
        parser.error(f"Image introuvable : {src}")

    formats = {s.strip().lower() for s in args.formats.split(",") if s.strip()}
    dest = (args.output or src.with_name(src.stem + "_recuperation_videos")).expanduser().resolve()
    configure_logging(dest if not args.dry_run else None, args.verbose, args.quiet)

    log.info("=" * 68)
    log.info("CARVING PRUDENT (IMAGES & VIDÉOS) — SOURCE EN LECTURE SEULE")
    log.info("=" * 68)
    log.info("Formats recherchés : %s", ", ".join(sorted(formats)))

    if not args.dry_run:
        dest.mkdir(parents=True, exist_ok=True)

    def progress(done, total):
        """Display scan progress unless quiet mode is enabled."""
        if args.quiet:
            return
        pct = 100 * done / max(1, total)
        sys.stdout.write(f"\rAnalyse : {pct:5.1f}%")
        sys.stdout.flush()

    try:
        candidates, image_size = scan_signatures(
        src, args.workers, args.chunk_mib * MIB, progress_cb=progress
    )
    except RecupError as e:
        print()
        log.error("Échec du scan : %s", e)
        return 1
    print()

    candidates = [c for c in candidates if c[1] in formats]
    log.info("Signatures candidates trouvées : %d", len(candidates))

    all_offsets = [o for o, _ in candidates]
    manifest_path = dest / "manifest.jsonl"
    stats = RunStats()
    records: list[dict] = []
    ranges: list[tuple[int, int]] = []
    seen_hashes: set[str] = set()

    if args.resume and not args.dry_run:
        records, _covered_starts, seen_hashes = load_existing_manifest(manifest_path)
        for r in records:
            ranges.append((r["offset_decimal"], r["offset_decimal"] + r["size_bytes"]))
            stats.counts[r["type"]] = stats.counts.get(r["type"], 0) + 1
            if r.get("anomaly"):
                stats.anomalies += 1
            if r.get("corrected_file"):
                stats.corrected += 1
        stats.extracted = len(records)
        log.info("Reprise : %d fichiers déjà récupérés.", stats.extracted)
        manifest_mode = "a"
    else:
        manifest_mode = "w"

    mf = None
    f = None
    try:
        if not args.dry_run:
            mf = open(manifest_path, manifest_mode, encoding="utf-8")
        f = open(src, "rb", buffering=0)

        for offset, ext in candidates:
            if any(a <= offset < b for a, b in ranges):
                continue

            next_off = next((o for o in all_offsets if o > offset), None)
            if ext == "png":
                length = png_length(f, offset, image_size)
            elif ext == "gif":
                length = gif_length(f, offset, image_size)
            elif ext == "bmp":
                length = bmp_length(f, offset, image_size)
            elif ext == "pdf":
                length = pdf_length(f, offset, image_size)
            else:
                length = video_length(f, offset, image_size, ext, next_off)

            if length is None or length < args.min_size or offset + length > image_size:
                stats.rejected += 1
                continue

            end = offset + length
            if any(offset < b and end > a for a, b in ranges):
                continue

            if args.dry_run:
                stats.counts[ext] = stats.counts.get(ext, 0) + 1
                stats.extracted += 1
                ranges.append((offset, end))
                continue

            stats.counts[ext] = stats.counts.get(ext, 0) + 1
            name = f"recup_{ext}_{stats.counts[ext]:06d}_offset_{offset:012x}.{ext}"
            out = dest / name

            try:
                with open(out, "xb", buffering=0) as of:
                    f.seek(offset)
                    remaining = length
                    while remaining:
                        block = f.read(min(WRITE_CHUNK, remaining))
                        if not block:
                            break
                        of.write(block)
                        remaining -= len(block)
            except (OSError, FileExistsError) as e:
                log.warning("Erreur d'écriture à l'offset %#x: %s", offset, e)
                continue

            digest = hash_file(out)
            if not args.no_dedup and digest in seen_hashes:
                out.unlink(missing_ok=True)
                stats.duplicates += 1
                stats.counts[ext] -= 1
                continue
            seen_hashes.add(digest)

            stats.extracted += 1

            val = image_validate(out, ext)
            video_meta = {}
            corrected_info = None

            if ext in ("mp4", "mkv", "mov", "avi") and length > 500 * MIB:
                video_meta = analyze_large_video(out, length)
                if video_meta.get("anomaly"):
                    stats.anomalies += 1
                    log.warning(
                "ANOMALIE DÉTECTÉE sur %s : %s",
                name, video_meta.get("anomaly_reason"),
            )

                    log.info(
                        "Lancement de la correction automatique dans le dossier principal..."
                    )
                    res_corr = correct_video_with_ffmpeg(out, dest, ext)
                    if res_corr:
                        corr_path, corr_hash = res_corr
                        stats.corrected += 1
                        corrected_info = {
                            "corrected_file": str(corr_path.relative_to(dest)),
                            "corrected_size_bytes": corr_path.stat().st_size,
                            "corrected_sha256": corr_hash
                        }
                        log.info(
                            "Succès de la correction -> Fichier enregistré : %s",
                            corr_path.name,
                        )

            rec = {
                "file": name,
                "type": ext,
                "offset_hex": hex(offset),
                "offset_decimal": offset,
                "size_bytes": length,
                "sha256": digest,
                **val,
                **video_meta,
                **(corrected_info or {})
            }
            records.append(rec)
            ranges.append((offset, end))

            if mf is not None:
                mf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                mf.flush()

            if args.max_files and stats.extracted >= args.max_files:
                break
    finally:
        if mf is not None:
            mf.close()
        if f is not None:
            f.close()

    if args.dry_run:
        log.info("Mode dry-run terminé. Estimations : %s", stats.counts)
        return 0

    csv_path = dest / "rapport_recuperation.csv"
    fields = [
        "file", "type", "offset_hex", "offset_decimal", "size_bytes", "sha256",
        "validation", "video_analysis", "duration_sec", "bitrate_kbps", "anomaly", "anomaly_reason",
        "corrected_file", "corrected_size_bytes", "corrected_sha256", "error"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as cf:
        w = csv.DictWriter(cf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)

    rows = []
    for r in records:
        anomaly_badge = (
            "<span style='color:red;font-weight:bold;'>OUI</span>"
            if r.get("anomaly") else "Non"
        )
        corr_info = html.escape(r.get("corrected_file", "")) if r.get("corrected_file") else "-"
        size_mio = r['size_bytes'] / MIB
        dur = f"{r.get('duration_sec', 0):.1f}s" if r.get('duration_sec') is not None else "N/A"
        bitrate = f"{r.get('bitrate_kbps', 0)} kbps" if r.get('bitrate_kbps') is not None else "N/A"
        rows.append(
            f"<tr><td>{html.escape(r['file'])}</td><td>{r['type']}</td><td>{size_mio:.2f} Mio</td>"
            f"<td>{dur}</td><td>{bitrate}</td><td>{anomaly_badge}</td>"
            f"<td>{corr_info}</td><td><code>{r['sha256'][:12]}</code></td></tr>"
        )

    html_path = dest / "rapport_recuperation.html"
    html_path.write_text(
        "<!doctype html><html lang='fr'><meta charset='utf-8'><title>Rapport Vidéo</title>"
        "<style>body{font:14px sans-serif;margin:24px}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:left}th{background:#eee}</style>"
        "<h1>Rapport de Récupération (Vidéos & Médias)</h1>"
        f"<p>Source : {html.escape(str(src))}</p>"
        f"<p>Extraits : {stats.extracted} | Doublons : {stats.duplicates} | "
        f"Rejetés : {stats.rejected} | Anomalies : {stats.anomalies} | "
        f"Corrigées : {stats.corrected}</p>"
        "<table><thead><tr><th>Fichier</th><th>Type</th><th>Taille</th>"
        "<th>Durée</th><th>Débit</th><th>Anomalie</th>"
        "<th>Fichier Corrigé</th><th>SHA-256</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></html>",
        encoding="utf-8",
    )

    log.info("Terminé avec succès. Fichiers sauvegardés dans : %s", dest)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.")
        sys.exit(130)
    except RecupError as exc:
        print(f"\nERREUR : {exc}", file=sys.stderr)
        sys.exit(1)
