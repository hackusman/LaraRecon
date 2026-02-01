# 🔍 LaraRecon - Laravel Security Scanner

> Automated security scanner for Laravel applications.

---

## 🚀 Quick Start

```bash
# Clone & Install
git clone https://github.com/hackusman/LaraRecon.git
cd LaraRecon
pip install -r requirements.txt

# Run Scanner
python app.py
```

➡️ Open browser: **http://localhost:5000**

---

## 📋 Requirements
- Python 3.8+
- Modern web browser (Chrome, Firefox, Edge)

---

## 🔄 Usage Flow
1. Enter target URL (e.g., `https://your-laravel-app.com`)
2. Click **"INITIATE SCAN"**
3. Watch real-time progress (18-25 seconds)
4. View color-coded results:
   - 🔴 Critical vulnerabilities
   - 🟡 Warnings
   - 🟢 Secure items
5. Download reports:
   - 📄 TXT (plain text)
   - ⚙️ JSON (structured data)
   - 🌐 HTML (interactive report)

> 💡 *The `reports/` folder auto-creates on first scan*

---

## 📁 Project Structure
```
LaraRecon/
├── app.py              # Core scanner engine
├── requirements.txt    # Dependencies
├── reports/            # Auto-generated scan reports
├── templates/          # Web interface (index/results)
└── static/
    ├── css/style.css   # Hacker terminal theme
    └── js/script.js    # Real-time scanning logic
```

---

## ⚠️ Critical Legal Notice
> **AUTHORIZED USE ONLY**  
> This tool is strictly for security testing on systems **you own** or have **written permission** to test.  
> Unauthorized scanning violates computer fraud laws in most jurisdictions.  
> *You are solely responsible for your actions.*

---

## 💡 Pro Tips
- Scan your **own staging environment** first
- Always get **written authorization** before scanning client systems
- Use HTML reports for professional vulnerability documentation
- Check `reports/` folder if download buttons fail

---

## 👤 Author
**hackus_man**

---

> 🔒 LaraRecon v1.0 • Scan Fast • Stay Ethical • Secure Laravel  
> *"With great power comes great responsibility"* 🕷️
