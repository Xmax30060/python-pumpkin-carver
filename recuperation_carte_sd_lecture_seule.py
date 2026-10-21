#!/usr/bin/env python3
# Imagerie de volume Windows en lecture seule, avec reprise après interruption.
# Vérifiez DRIVE et enregistrez l'image sur un AUTRE disque physique.
# Cette méthode lit le volume logique \\.\E:, pas nécessairement toute la carte physique.

import ctypes
from ctypes import wintypes
import os
import sys
import time
import json
import shutil
from pathlib import Path

DRIVE = "E:"
CHUNK = 8 * 1024 * 1024  # 8 Mio; réduisez à 1 Mio si les déconnexions persistent.
RETRIES = 3
RETRY_DELAY_SECONDS = 1.5
OUTPUT_DIR = Path.home() / "Downloads" / "recup_carte_sd"
IMAGE_PATH = OUTPUT_DIR / "carte_sd.img"
STATE_PATH = OUTPUT_DIR / "carte_sd_progress.json"

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
CreateFileW.restype = wintypes.HANDLE
DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                            wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
DeviceIoControl.restype = wintypes.BOOL
ReadFile = kernel32.ReadFile
ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                     ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
ReadFile.restype = wintypes.BOOL
GetOverlappedResult = kernel32.GetOverlappedResult
GetOverlappedResult.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
GetOverlappedResult.restype = wintypes.BOOL
CreateEventW = kernel32.CreateEventW
CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
CreateEventW.restype = wintypes.HANDLE
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


def win_error(message):
    code = ctypes.get_last_error()
    return OSError(code, f"{message}: {ctypes.FormatError(code)}")


def open_source(overlapped=False):
    flags = FILE_ATTRIBUTE_NORMAL | (FILE_FLAG_OVERLAPPED if overlapped else 0)
    handle = CreateFileW(r"\\.\{}".format(DRIVE), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                         OPEN_EXISTING, flags, None)
    if handle == INVALID_HANDLE_VALUE:
        raise win_error("Impossible d'ouvrir le volume. Essayez en administrateur")
    return handle


def get_size(handle):
    length = ctypes.c_longlong()
    returned = wintypes.DWORD()
    if not DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0,
                           ctypes.byref(length), ctypes.sizeof(length),
                           ctypes.byref(returned), None):
        raise win_error("Impossible de lire la taille du volume")
    if length.value <= 0:
        raise RuntimeError("Taille de volume invalide")
    return length.value


def read_chunk(handle, size):
    buf = ctypes.create_string_buffer(size)
    got = wintypes.DWORD()
    if not ReadFile(handle, buf, size, ctypes.byref(got), None):
        raise win_error("Erreur de lecture")
    if got.value == 0:
        raise OSError("Le lecteur a retourné zéro octet")
    return buf.raw[:got.value]


def save_state(total, done):
    tmp = STATE_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"drive": DRIVE, "total": total, "done": done,
                   "chunk": CHUNK}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_PATH)


def image_volume():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Source : \\\\.\\{DRIVE}")
    print(f"Image  : {IMAGE_PATH}")
    print(f"Taille de bloc : {CHUNK // (1024*1024)} Mio")
    print("Lecture seule de la source. Confirmez que E: est bien la carte SD.")
    if input("Tapez OUI pour continuer : ").strip() != "OUI":
        print("Annulé.")
        return

    handle = None
    try:
        handle = open_source()
        total = get_size(handle)
        done = 0

        if IMAGE_PATH.exists():
            image_size = IMAGE_PATH.stat().st_size
            done = min(image_size, total)
            if STATE_PATH.exists():
                try:
                    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
                    if (state.get("drive") != DRIVE or
                            int(state.get("total", -1)) != total):
                        print("L'état sauvegardé ne correspond pas à la source actuelle ; arrêt prudent.")
                        return
                    # Ne jamais faire confiance à un point de reprise au-delà de l'image réelle.
                    done = min(done, max(0, int(state.get("done", 0))))
                except Exception as e:
                    print(f"Fichier de progression illisible ({e}).")
                    print("La reprise utilisera la taille réelle de l'image, arrondie au bloc complet.")
                    done = min(image_size, total)
            # Si la coupure est survenue entre deux sauvegardes de progression,
            # reprendre au dernier bloc complet présent dans le fichier.
            done = (done // CHUNK) * CHUNK
            print(f"Image existante détectée : {image_size/(1024**3):.2f} Gio.")
            print(f"Reprise à l'offset sûr : {done/(1024**3):.2f} Gio.")
            save_state(total, done)
        elif STATE_PATH.exists():
            print("Fichier de progression présent mais image absente ; arrêt prudent.")
            return
        else:
            free = shutil.disk_usage(OUTPUT_DIR).free
            if free < total + 100 * 1024 * 1024:
                raise RuntimeError(f"Espace libre insuffisant : {free/(1024**3):.2f} Gio.")
            with open(IMAGE_PATH, "xb") as f:
                f.flush()
                os.fsync(f.fileno())
            save_state(total, 0)

        if done == total:
            print("Image déjà complète.")
            return

        # L'image doit contenir tous les octets validés; tronquer une éventuelle fin non validée.
        with open(IMAGE_PATH, "r+b", buffering=0) as out:
            out.truncate(done)
            out.seek(done)
            while done < total:
                want = min(CHUNK, total - done)
                chunk_data = None
                last_error = None

                for attempt in range(1, RETRIES + 1):
                    if handle is not None:
                        CloseHandle(handle)
                        handle = None
                    try:
                        # Contrôler la taille avec un handle normal, puis ouvrir un handle
                        # overlapped pour lire à l'offset exact.
                        check_handle = open_source(False)
                        try:
                            current_total = get_size(check_handle)
                        finally:
                            CloseHandle(check_handle)
                        if current_total != total:
                            raise RuntimeError("La taille du volume a changé ; arrêt.")
                        handle = open_source(True)
                        chunk_data = read_at(handle, done, want)
                        if not chunk_data:
                            raise OSError("Lecture vide")
                        break
                    except Exception as e:
                        last_error = e
                        print(f"\nLecture interrompue à {done/(1024**3):.3f} Gio "
                              f"(essai {attempt}/{RETRIES}) : {e}")
                        if attempt < RETRIES:
                            time.sleep(RETRY_DELAY_SECONDS)

                if chunk_data is None:
                    out.flush()
                    os.fsync(out.fileno())
                    save_state(total, done)
                    print(f"\nArrêt sécurisé. Progression sauvegardée à {done/(1024**3):.3f} Gio.")
                    print("Vérifiez le lecteur USB, les contacts et la carte, puis relancez le script.")
                    print("Il tentera de reprendre à cet offset.")
                    return

                out.write(chunk_data)
                done += len(chunk_data)
                # Synchronisation périodique : au plus environ 128 Mio à relire après coupure.
                if done % (128 * 1024 * 1024) < CHUNK or done == total:
                    out.flush()
                    os.fsync(out.fileno())
                    save_state(total, done)
                    print(f"\rImage : {100*done/total:6.2f}% "
                          f"({done/(1024**3):.2f}/{total/(1024**3):.2f} Gio)", end="", flush=True)

        print("\nImage terminée :", IMAGE_PATH)
    finally:
        if handle is not None:
            CloseHandle(handle)


# ReadFile avec OVERLAPPED permet de lire à un offset explicite.
def read_at(handle, offset, size):
    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    ov = OVERLAPPED()
    ov.Offset = offset & 0xFFFFFFFF
    ov.OffsetHigh = (offset >> 32) & 0xFFFFFFFF
    event = CreateEventW(None, True, False, None)
    if not event:
        raise win_error("Impossible de créer l'événement de lecture")
    ov.hEvent = event
    buf = ctypes.create_string_buffer(size)
    got = wintypes.DWORD()
    try:
        ok = ReadFile(handle, buf, size, ctypes.byref(got), ctypes.byref(ov))
        if not ok:
            err = ctypes.get_last_error()
            ERROR_IO_PENDING = 997
            if err != ERROR_IO_PENDING:
                raise OSError(err, f"Lecture à l'offset {offset} impossible: {ctypes.FormatError(err)}")
            if not GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(got), True):
                raise win_error(f"Lecture à l'offset {offset} impossible")
        if got.value == 0:
            return b""
        return buf.raw[:got.value]
    finally:
        CloseHandle(event)


def main():
    if os.name != "nt":
        print("Ce script est prévu pour Windows.")
        return
    print("=" * 64)
    print("CARTE SD - IMAGER EN LECTURE SEULE AVEC REPRISE")
    print("=" * 64)
    print("Conseil : fermez l'Explorateur Windows et les applications qui utilisent E:.")
    print("Un lecteur USB/carte instable peut encore interrompre la copie.")
    image_volume()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nARRÊT : {exc}")
        print("Aucune écriture volontaire n'a été faite sur la source.")
    input("\nAppuyez sur Entrée pour fermer...")
