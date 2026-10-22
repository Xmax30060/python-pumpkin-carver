<div align="center">

# 🎃 Pumpkin Carver

**Entreprise-Grade Disk Imaging & Data Recovery Solution**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

*Une solution robuste et modulaire de récupération de données et d'extraction de fichiers par signature numérique pour volumes corrompus ou inaccessibles.*

</div>

---

## 📑 Table des matières

- [Présentation](#-présentation)
- [Architecture du projet](#-architecture-du-projet)
- [Prérequis système & Dépendances](#-prérequis-système--dépendances)
- [Installation de FFmpeg](#-installation-de-ffmpeg)
- [Guides d'utilisation](#-guides-dutilisation)
  - [Option 1 : Prototypes CLI Modulaires](#option-1--prototypes-cli-modulaires)
  - [Option 2 : Application Graphique Intégrée](#option-2--application-graphique-intégrée)
- [Fonctionnalités clés](#-fonctionnalités-clés)
- [Recommandations & Sécurité](#-recommandations--sécurité)
- [Licence](#-licence)

---

## 🎯 Présentation

**Pumpkin Carver** est une suite logicielle développée en Python permettant d'extraire des images, vidéos et documents à partir d'images disques brutes (`.img`). En exploitant le *file carving* basé sur les signatures et magic bytes, l'application permet de reconstituer des fichiers même lorsque la table de partition ou le système de fichiers est endommagé.

Le projet propose deux approches adaptées à différents besoins :
1. **Modules CLI distincts :** Pour des interventions rapides, ciblées ou automatisées.
2. **Interface Graphique Intégrée (GUI) :** Pour une expérience utilisateur complète combinant acquisition et extraction.

---

## 📁 Architecture du projet

```text
Pumpkin-Carver/
├── 📄 README.md
├── 📄 LICENSE
├── 📂 CLI_per_role_source_code/       # Outillage en ligne de commande (CLI)
│   ├── 📜 Imager.py                  # Module d'acquisition d'image disque (Windows)
│   ├── 📜 Video_Carving_only.py      # Carving ciblé flux vidéo
│   └── 📜 Image&Document_carving.py  # Carving documents et images
│
└── 📂 UI_AllInOne_source_code/        # Application avec interface graphique (GUI)    
    └── 📜 pumpkin_carver_integrated_v2.py # GUI v2 
