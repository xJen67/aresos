import http.server
import socketserver
import os
import urllib.parse
import cgi
import http.cookies
import hashlib
import time
import secrets
from datetime import datetime

PORT = 8080
UPLOAD_DIR = "uploads"
PASSWORD_FILE = "Mot De Passe.txt"
LOG_FILE = "server.log"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs("temp_shares", exist_ok=True)

sessions = {}
temp_links = {}

def log_activity(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    print(log_entry.strip())
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing to log: {e}")

def load_users():
    users = {}
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    users[parts[0]] = parts[1]
    return users

class SecureHandler(http.server.BaseHTTPRequestHandler):
    def get_current_user(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = http.cookies.SimpleCookie(cookie_header)
            if 'session_id' in cookie:
                session_id = cookie['session_id'].value
                return sessions.get(session_id)
        return None

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        user = self.get_current_user()

        if path.startswith("/download_temp/"):
            token = path.split("/")[-1]
            if token in temp_links:
                file_info = temp_links[token]
                if time.time() > file_info["expires"]:
                    del temp_links[token]
                    self.send_error(410, "Link expired")
                    log_activity(f"ALERTE 410 : Expired temp link accessed")
                    return
                filepath = file_info["path"]
                if os.path.exists(filepath):
                    self.send_response(200)
                    self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(filepath)}"')
                    self.end_headers()
                    with open(filepath, "rb") as f:
                        self.wfile.write(f.read())
                    log_activity(f"Téléchargement par lien temporaire : {os.path.basename(filepath)}")
                    return
            self.send_error(404, "Invalid or expired link")
            return

        if not user:
            self.send_login_page()
            return

        if path == "/":
            self.send_dashboard(user)
        elif path.startswith("/uploads/"):
            rel_path = path[len("/uploads/"):]
            parts = rel_path.split("/", 1)
            target_user = parts[0]

            if user != "Admin" and user != target_user:
                log_activity(f"ALERTE 403 : {user} a tenté d'accéder au dossier de {target_user}")
                self.send_error(403, "Accès refusé à ce dossier.")
                return

            filepath = os.path.join(UPLOAD_DIR, rel_path)
            if os.path.exists(filepath) and os.path.isfile(filepath):
                self.send_response(200)
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(filepath)}"')
                self.end_headers()
                with open(filepath, "rb") as f:
                    self.wfile.write(f.read())
                log_activity(f"Téléchargement : {user} a téléchargé {os.path.basename(filepath)}")
            else:
                self.send_error(404, "Fichier introuvable.")
        elif path == "/logout":
            log_activity(f"Déconnexion : {user}")
            self.send_response(303)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', 'session_id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/')
            self.end_headers()
        else:
            log_activity(f"ALERTE 404 : {user} a tenté d'accéder à {path}")
            self.send_error(404, "Page non trouvée")

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/login":
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                }
            )
            username = form.getvalue("username")
            password = form.getvalue("password")
            users = load_users()

            if username in users and users[username] == password:
                session_id = secrets.token_hex(16)
                sessions[session_id] = username
                log_activity(f"Succès de connexion : {username}")
                self.send_response(303)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly')
                self.end_headers()
            else:
                log_activity(f"Échec de connexion : tentative pour l'utilisateur '{username}'")
                self.send_login_page("Identifiant ou mot de passe incorrect.")
        
        elif path == "/upload":
            user = self.get_current_user()
            if not user:
                self.send_error(401, "Non autorisé")
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                }
            )
            
            user_folder = os.path.join(UPLOAD_DIR, user)
            os.makedirs(user_folder, exist_ok=True)

            if "file" in form:
                fileitem = form["file"]
                if fileitem.filename:
                    filename = os.path.basename(fileitem.filename)
                    filepath = os.path.join(user_folder, filename)
                    with open(filepath, "wb") as f:
                        f.write(fileitem.file.read())
                    log_activity(f"Upload : {user} a mis en ligne {filename}")

            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()

        elif path == "/delete":
            user = self.get_current_user()
            if not user:
                self.send_error(401, "Non autorisé")
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                }
            )
            file_to_delete = form.getvalue("file_path")
            if file_to_delete:
                rel_path = file_to_delete.replace("/uploads/", "")
                parts = rel_path.split("/", 1)
                file_owner = parts[0]

                if user == "Admin" or user == file_owner:
                    full_path = os.path.join(UPLOAD_DIR, rel_path)
                    if os.path.exists(full_path):
                        os.remove(full_path)
                        log_activity(f"Suppression : {user} a supprimé {rel_path}")

            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()

        elif path == "/share":
            user = self.get_current_user()
            if not user:
                self.send_error(401, "Non autorisé")
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                }
            )
            file_to_share = form.getvalue("file_path")
            if file_to_share:
                rel_path = file_to_share.replace("/uploads/", "")
                parts = rel_path.split("/", 1)
                file_owner = parts[0]

                if user == "Admin" or user == file_owner:
                    full_path = os.path.join(UPLOAD_DIR, rel_path)
                    if os.path.exists(full_path):
                        token = secrets.token_urlsafe(16)
                        temp_links[token] = {
                            "path": full_path,
                            "expires": time.time() + 3600 
                        }
                        log_activity(f"Partage temp : {user} a généré un lien pour {rel_path}")
                        self.send_dashboard(user, share_link=f"/download_temp/{token}")
                        return

            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()

    def send_login_page(self, error=""):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Connexion</title>
            <style>
                body {{ font-family: sans-serif; background: #f4f4f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                .login-box {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 300px; }}
                h2 {{ margin-top: 0; color: #333; text-align: center; }}
                input {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
                .password-container {{ position: relative; }}
                .eye-icon {{ position: absolute; right: 10px; top: 18px; cursor: pointer; user-select: none; }}
                button {{ width: 100%; padding: 10px; background: #007BFF; border: none; color: white; border-radius: 4px; cursor: pointer; font-weight: bold; }}
                button:hover {{ background: #0056b3; }}
                .error {{ color: red; font-size: 0.9em; text-align: center; margin-bottom: 10px; }}
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>Connexion Sécurisée</h2>
                {'<div class="error">' + error + '</div>' if error else ''}
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Nom d'utilisateur" required>
                    <div class="password-container">
                        <input type="password" id="password" name="password" placeholder="Mot de passe" required>
                        <span class="eye-icon" onclick="togglePassword()">👁️</span>
                    </div>
                    <button type="submit">Se connecter</button>
                </form>
            </div>
            <script>
                function togglePassword() {{
                    const pwdInput = document.getElementById('password');
                    if (pwdInput.type === 'password') {{
                        pwdInput.type = 'text';
                    }} else {{
                        pwdInput.type = 'password';
                    }}
                }}
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

    def send_dashboard(self, user, share_link=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        folders_to_show = []
        if user == "Admin":
            if os.path.exists(UPLOAD_DIR):
                folders_to_show = os.listdir(UPLOAD_DIR)
        else:
            folders_to_show = [user]
            user_path = os.path.join(UPLOAD_DIR, user)
            os.makedirs(user_path, exist_ok=True)

        files_html = ""
        for folder in folders_to_show:
            folder_path = os.path.join(UPLOAD_DIR, folder)
            if os.path.isdir(folder_path):
                files_html += f"<h3>Dossier : {folder}</h3><ul>"
                items = os.listdir(folder_path)
                if not items:
                    files_html += "<li><i>Aucun fichier</i></li>"
                for item in items:
                    item_path = os.path.join(folder_path, item)
                    if os.path.isfile(item_path):
                        file_url = f"/uploads/{folder}/{item}"
                        can_delete = (user == "Admin" or user == folder)
                        
                        delete_form = ""
                        if can_delete:
                            delete_form = f"""
                            <form action="/delete" method="POST" style="display:inline; margin-left: 10px;">
                                <input type="hidden" name="file_path" value="{file_url}">
                                <button type="submit" style="background:#dc3545; padding:2px 8px; font-size:0.8em;">Supprimer</button>
                            </form>
                            <form action="/share" method="POST" style="display:inline; margin-left: 5px;">
                                <input type="hidden" name="file_path" value="{file_url}">
                                <button type="submit" style="background:#ffc107; color:black; padding:2px 8px; font-size:0.8em;">Partager (1h)</button>
                            </form>
                            """
                        files_html += f"<li><a href='{file_url}' target='_blank'>{item}</a>{delete_form}</li>"
                files_html += "</ul>"

        share_banner = ""
        if share_link:
            full_link = f"http://localhost:{PORT}{share_link}"
            share_banner = f"""
            <div style="background: #e2f0d9; padding: 10px; margin-bottom: 15px; border-left: 4px solid #385723;">
                <strong>Lien temporaire généré (valide 1h) :</strong> <a href="{share_link}" target="_blank">{full_link}</a>
            </div>
            """

        html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Tableau de bord</title>
            <style>
                body {{ font-family: sans-serif; background: #f4f4f9; margin: 0; padding: 20px; }}
                .container {{ max-width: 800px; background: white; padding: 20px; margin: auto; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }}
                .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
                button {{ background: #007BFF; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; }}
                button:hover {{ background: #0056b3; }}
                .logout {{ background: #dc3545; text-decoration: none; padding: 8px 12px; color: white; border-radius: 4px; }}
                .logout:hover {{ background: #c82333; }}
                ul {{ padding-left: 20px; }}
                li {{ margin: 8px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Bienvenue, {user} !</h2>
                    <a href="/logout" class="logout">Se déconnecter</a>
                </div>
                {share_banner}
                <h3>Use/Mettre en ligne un fichier</h3>
                <form action="/upload" method="POST" enctype="multipart/form-data">
                    <input type="file" name="file" required>
                    <button type="submit">Envoyer</button>
                </form>
                <hr>
                <h2>Fichiers disponibles</h2>
                {files_html}
            </div>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), SecureHandler) as httpd:
        print(f"Serveur actif sur le port {PORT}...")
        log_activity("Serveur démarré.")
        httpd.serve_forever()
