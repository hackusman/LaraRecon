# LaraRecon Web Edition
# Author: hackus_man

from flask import Flask, render_template, request
import requests

app = Flask(__name__)

SENSITIVE_PATHS = [

    # --- ENV / SECRETS ---
    ".env", ".env.backup", ".env.old", ".env.save", ".env.bak",
    ".env.dev", ".env.prod", ".env.local", ".env.example",
    ".env~", ".env.swp",

    # --- LARAVEL CORE ---
    "artisan",
    "server.php",
    "composer.json", "composer.lock",
    "package.json", "yarn.lock",
    "routes/web.php", "routes/api.php", "routes/channels.php",
    "bootstrap/app.php",
    "bootstrap/cache/config.php",
    "bootstrap/cache/routes.php",
    "bootstrap/cache/services.php",

    # --- CONFIG ---
    "config/app.php", "config/auth.php", "config/database.php",
    "config/cache.php", "config/filesystems.php",
    "config/mail.php", "config/queue.php",
    "config/services.php", "config/session.php",

    # --- STORAGE ---
    "storage/logs/laravel.log",
    "storage/logs/*.log",
    "storage/framework/sessions/",
    "storage/framework/views/",
    "storage/framework/cache/",

    # --- DEBUG ---
    "_ignition/execute-solution",
    "_ignition/health-check",
    "_debugbar",
    "_debugbar/open",
    "debug/default/view",

    # --- GIT / VCS ---
    ".git/config", ".git/HEAD", ".git/index",
    ".git/logs/HEAD", ".gitignore",

    # --- IDE ---
    ".idea/workspace.xml",
    ".idea/modules.xml",
    ".vscode/settings.json",

    # --- BACKUPS ---
    "backup.zip", "site.zip", "www.zip", "laravel.zip",
    "backup.tar.gz", "www.tar.gz",
    "database.sql", "dump.sql", "db.sql",
    "backup.sql", "site.sql",

    # --- PUBLIC MISCONFIG ---
    "phpinfo.php",
    "info.php",
    "test.php",

    # --- API ---
    "api/swagger",
    "api/swagger.json",
    "swagger",
    "swagger.json",
    "openapi.json",
    "v3/api-docs",

    # --- AUTH / ADMIN ---
    "admin",
    "admin/login",
    "login",
    "register",
    "dashboard",

    # --- FILES ---
    ".htaccess",
    "public/.htaccess",
    "web.config",

    # --- CI / DEVOPS ---
    ".github/workflows/main.yml",
    ".gitlab-ci.yml",
    "docker-compose.yml",
    "Dockerfile",

    # --- CACHE ---
    ".cache",
    "cache",
    "tmp",
    "temp",

    # --- MISC ---
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml"
]

def scan_target(url):
    results = []

    for path in SENSITIVE_PATHS:
        full = f"{url.rstrip('/')}/{path}"
        try:
            r = requests.get(full, timeout=5)

            if r.status_code == 200 and len(r.text) > 20:
                if ".env" in path:
                    level = "Critique"
                elif "log" in path or "config" in path:
                    level = "Élevé"
                else:
                    level = "Moyen"

                results.append({
                    "path": path,
                    "url": full,
                    "status": r.status_code,
                    "size": len(r.text),
                    "level": level,
                    "reason": "Fichier sensible accessible publiquement."
                })

        except:
            pass

    return results


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        url = request.form.get("url")
        results = scan_target(url)

    return render_template("index.html", results=results)


if __name__ == "__main__":
    app.run(debug=True)

