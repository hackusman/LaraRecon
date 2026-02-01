# 🔍 LaraRecon

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

### 📌 Description
LaraRecon is an automated security scanner specifically designed for Laravel applications. It detects exposed sensitive files (`.env`, logs, backups), misconfigured debug endpoints (Telescope, Horizon, Ignition), version-specific vulnerabilities, and critical CVEs — all through a sleek hacker-themed web interface.

### 📋 Requirements
- Python 3.8 or higher
- pip package manager

### ⚙️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/hackusman/LaraRecon.git
cd LaraRecon

# 2. Install dependencies
pip install -r requirements.txt


### ▶️ Usage

```bash
# Start the scanner
python app.py
```

### 📁 Project Structure
```
lararecon/
├── app.py              # Main scanner application
├── requirements.txt    # Python dependencies
├── reports/            # Generated scan reports (auto-created)
├── templates/          # Web interface templates
└── static/             # CSS/JS assets (hacker theme)
```

### ⚠️ Legal Notice
This tool is for **authorized security testing only**. Never scan systems you don't own or have explicit permission to test. Unauthorized scanning may be illegal.

---


- Python 3.8 ou supérieur
- Gestionnaire de paquets pip

### ⚙️ Installation

```bash
# 1. Cloner le dépôt
git clone https://github.com/hackus-man/lararecon.git
cd lararecon

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Créer le dossier des rapports (créé automatiquement au premier lancement)
mkdir -p reports
```

### ▶️ Utilisation

```bash
# Démarrer le scanner
python app.py
```

1. Ouvrez votre navigateur : `http://localhost:5000`
2. Entrez l'URL cible (ex: `https://votre-app-laravel.com`)
3. Cliquez sur **"INITIATE SCAN"**
4. Attendez 20 secondes pour la fin du scan
5. Téléchargez les rapports (TXT/JSON/HTML) depuis la page de résultats

### 📁 Structure du Projet
```
lararecon/
├── app.py              # Application principale du scanner
├── requirements.txt    # Dépendances Python
├── reports/            # Rapports de scan générés (créé automatiquement)
├── templates/          # Templates de l'interface web
└── static/             # Assets CSS/JS (thème hacker)
```

### ⚠️ Avertissement Légal
This tool is intended **only for authorized security testing**. Never scan systems you do not own or for which you do not have explicit permission. Unauthorized scanning may be illegal.
---

## 👤 Author
**hackus_man**  

---

> 🔒 LaraRecon v1.0 - Specialized Laravel Security Scanner  
> *Scan fast. Stay ethical. Secure Laravel.*
