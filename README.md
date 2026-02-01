# 🔍 LaraRecon

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

# Start the scanner
python app.py


### 📁 Project Structure
```
lararecon/
├── app.py              # Main scanner application
├── requirements.txt    # Python dependencies
├── reports/            # Generated scan reports (auto-created)
├── templates/          # Web interface templates
└── static/             # CSS/JS assets (hacker theme)
```


## 👤 Author
**hackus_man**  

---

> 🔒 LaraRecon v1.0 - Specialized Laravel Security Scanner  
> *Scan fast. Stay ethical. Secure Laravel.*
