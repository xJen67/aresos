import http.server
import os
import urllib.parse
import html
import shutil
import uuid
import datetime
import hashlib
from http import cookies

EXTERNAL_CLOUD_LINK = "https://drive.google.com"

def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}\n"
    print(log_line.strip())
    try:
        with open("server.log", "a", encoding="utf-8") as log_file:
            log_file.write(log_line)
    except Exception as e:
        print(f"[!] Erreur d'écriture dans server.log : {e}")

def load_users():
    filename = "Mot De Passe.txt"
    users_db = {}
    current_user = None
    current_pass = None
    current_role = "user"
    
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    parts = line.split(":", 1)
                    key = parts[0].strip().lower()
                    val = parts[1].strip()
                    
                    if key == "user":
                        if current_user:
                            users_db[current_user] = {"password": current_pass, "role": current_role}
                        current_user = val
                        current_pass = None
                        current_role = "user"
                    elif key == "password":
                        current_pass = hashlib.sha256(val.encode('utf-8')).hexdigest()
                    elif key == "role":
                        current_role = val.lower()
                
                if current_user and current_pass:
                    users_db[current_user] = {"password": current_pass, "role": current_role}
                        
            log_event(f"[*] Fichier '{filename}' lu avec succès ! Comptes chargés : {list(users_db.keys())}")
        except Exception as e:
            log_event(f"[!] Erreur lors de la lecture du fichier : {e}")
    else:
        log_event(f"[!] Fichier '{filename}' introuvable. Compte de secours 'admin':'admin'")
        default_pass = hashlib.sha256("admin".encode('utf-8')).hexdigest()
        users_db["admin"] = {"password": default_pass, "role": "admin"}
        
    return users_db

def save_users_to_file():
    filename = "Mot De Passe.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for uname, data in USERS_DB.items():
                f.write(f"user: {uname}\n")
                f.write(f"role: {data['role']}\n\n")
        log_event("[*] Fichier des utilisateurs mis à jour.")
    except Exception as e:
        log_event(f"[!] Erreur sauvegarde utilisateurs : {e}")

USERS_DB = load_users()
SESSIONS = {}
FILE_OWNERS = {}
TEMP_LINKS = {}
FRIENDS = {}          # username -> list of friend usernames
PENDING_REQUESTS = {} # username -> list of usernames (demandes reçues)

UPLOAD_DIR = os.getcwd()
TRASH_DIR = os.path.join(UPLOAD_DIR, ".corbeille")
os.makedirs(TRASH_DIR, exist_ok=True)

COMMUN_DIR = os.path.join(UPLOAD_DIR, "Fichier commun")
os.makedirs(COMMUN_DIR, exist_ok=True)

for username in USERS_DB.keys():
    user_folder = os.path.join(UPLOAD_DIR, username)
    os.makedirs(user_folder, exist_ok=True)
    if username not in FRIENDS:
        FRIENDS[username] = []
    if username not in PENDING_REQUESTS:
        PENDING_REQUESTS[username] = []

class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def check_auth(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            try:
                c = cookies.SimpleCookie(cookie_header)
                if 'session_id' in c:
                    session_id = c['session_id'].value
                    if session_id in SESSIONS:
                        return SESSIONS[session_id]
            except Exception:
                pass
        return None

    def translate_path(self, path):
        path = super().translate_path(path)
        relpath = os.path.relpath(path, os.getcwd())
        return os.path.join(UPLOAD_DIR, relpath)

    def get_file_icon(self, filename, is_dir):
        if is_dir:
            return "bi-folder-fill text-warning"
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.url':
            return "bi-link-45deg text-success"
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp']:
            return "bi-file-earmark-image-fill text-primary"
        elif ext in ['.pdf']:
            return "bi-file-earmark-pdf-fill text-danger"
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            return "bi-file-earmark-zip-fill text-secondary"
        elif ext in ['.mp4', '.avi', '.mkv', '.mov']:
            return "bi-file-earmark-play-fill text-info"
        elif ext in ['.mp3', '.wav', '.ogg']:
            return "bi-file-earmark-music-fill text-info"
        elif ext in ['.py', '.bat', '.sh', '.js', '.html', '.css', '.json']:
            return "bi-file-earmark-code-fill text-dark"
        elif ext in ['.txt', '.md', '.doc', '.docx']:
            return "bi-file-earmark-text-fill text-secondary"
        return "bi-file-earmark-fill text-muted"

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        if parsed_url.path == "/login":
            self.send_login_page()
            return

        if parsed_url.path == "/logout":
            logged_in_user = self.check_auth()
            if logged_in_user:
                log_event(f"Déconnexion : {logged_in_user}")
            cookie_header = self.headers.get('Cookie')
            if cookie_header:
                try:
                    c = cookies.SimpleCookie(cookie_header)
                    if 'session_id' in c:
                        SESSIONS.pop(c['session_id'].value, None)
                except Exception:
                    pass
            self.send_response(303)
            self.send_header('Set-Cookie', 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.send_header('Location', '/login')
            self.end_headers()
            return

        logged_in_user = self.check_auth()
        if not logged_in_user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return

        user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")

        if parsed_url.path == "/admin":
            if user_role != "admin":
                self.send_forbidden("Accès réservé à l'administrateur.")
                return
            self.send_admin_dashboard(logged_in_user)
            return

        # Accepter une demande d'ami
        if parsed_url.path.startswith("/accept-friend/"):
            friend_name = parsed_url.path.split("/")[-1]
            if logged_in_user in PENDING_REQUESTS and friend_name in PENDING_REQUESTS[logged_in_user]:
                PENDING_REQUESTS[logged_in_user].remove(friend_name)
                if logged_in_user not in FRIENDS.setdefault(friend_name, []):
                    FRIENDS[friend_name].append(logged_in_user)
                if friend_name not in FRIENDS.setdefault(logged_in_user, []):
                    FRIENDS[logged_in_user].append(friend_name)
                log_event(f"Ami accepté : {friend_name} et {logged_in_user}")
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        if parsed_url.path == "/download-zip":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "dir" in query_params:
                rel_dir = query_params["dir"][0]
                target_dir = os.path.normpath(os.path.join(UPLOAD_DIR, rel_dir))
                if target_dir.startswith(UPLOAD_DIR) and os.path.isdir(target_dir):
                    first_folder = rel_dir.split('/')[0] if '/' in rel_dir else rel_dir
                    is_friend_folder = first_folder in FRIENDS.get(logged_in_user, [])
                    if user_role == "admin" or first_folder.lower() == "fichier commun" or first_folder == logged_in_user or is_friend_folder:
                        zip_filename = f"{os.path.basename(target_dir) or 'cloud'}.zip"
                        zip_path = shutil.make_archive(os.path.join(UPLOAD_DIR, "temp_archive"), 'zip', target_dir)
                        self.send_response(200)
                        self.send_header("Content-type", "application/zip")
                        self.send_header("Content-Disposition", f'attachment; filename="{zip_filename}"')
                        self.end_headers()
                        with open(zip_path, 'rb') as zf:
                            shutil.copyfileobj(zf, self.wfile)
                        os.remove(zip_path)
                        return
            self.send_forbidden("Accès refusé.")
            return

        if parsed_url.path == "/preview" or parsed_url.path == "/edit":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                if target_path.startswith(UPLOAD_DIR) and os.path.isfile(target_path):
                    first_folder = rel_file.split('/')[0] if '/' in rel_file else rel_file
                    is_friend_folder = first_folder in FRIENDS.get(logged_in_user, [])
                    if user_role == "admin" or first_folder.lower() == "fichier commun" or first_folder == logged_in_user or is_friend_folder:
                        ext = os.path.splitext(target_path)[1].lower()
                        filename = os.path.basename(target_path)
                        
                        if parsed_url.path == "/edit" and ext in ['.txt', '.py', '.js', '.css', '.html', '.json', '.md']:
                            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                            self.send_edit_page(rel_file, filename, content)
                            return

                        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg']:
                            mime = "image/png" if ext == '.png' else "image/jpeg"
                            self.send_response(200)
                            self.send_header("Content-type", mime)
                            self.end_headers()
                            with open(target_path, "rb") as f:
                                shutil.copyfileobj(f, self.wfile)
                            return
                        elif ext == '.pdf':
                            self.send_response(200)
                            self.send_header("Content-type", "application/pdf")
                            self.end_headers()
                            with open(target_path, "rb") as f:
                                shutil.copyfileobj(f, self.wfile)
                            return
                        elif ext in ['.txt', '.py', '.js', '.css', '.html', '.json', '.md']:
                            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                                text_content = html.escape(f.read())
                            self.send_response(200)
                            self.send_header("Content-type", "text/html; charset=utf-8")
                            self.end_headers()
                            self.wfile.write(f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
                            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                            <title>Aperçu - {filename}</title></head><body class="bg-dark text-light p-4">
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <h4 class="fw-bold m-0">{filename}</h4>
                                <a href="/edit?file={urllib.parse.quote(rel_file)}" class="btn btn-warning btn-sm"><i class="bi bi-pencil-square me-1"></i> Modifier</a>
                            </div>
                            <pre class="bg-secondary p-3 rounded text-light" style="white-space: pre-wrap;"><code>{text_content}</code></pre>
                            </body></html>""".encode('utf-8'))
                            return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Fichier non trouve.")
            return

        if parsed_url.path.startswith("/temp-download/"):
            token = parsed_url.path.split("/")[-1]
            if token in TEMP_LINKS:
                link_info = TEMP_LINKS[token]
                if datetime.datetime.now() < link_info["expires"]:
                    filepath = link_info["filepath"]
                    if os.path.exists(filepath):
                        self.send_file_content(filepath)
                        return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Lien expire.")
            return

        if parsed_url.path == "/generate-link":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                if target_path.startswith(UPLOAD_DIR):
                    if os.path.exists(target_path) and os.path.isfile(target_path):
                        token = str(uuid.uuid4())
                        expires = datetime.datetime.now() + datetime.timedelta(hours=24)
                        TEMP_LINKS[token] = {"filepath": target_path, "expires": expires}
                        host = self.headers.get('Host', 'localhost:8000')
                        temp_url = f"https://{host}/temp-download/{token}" if 'onrender.com' in host else f"http://{host}/temp-download/{token}"
                        
                        self.send_response(200)
                        self.send_header("Content-type", "text/html; charset=utf-8")
                        self.end_headers()
                        self.wfile.write(f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                        <title>Lien Temporaire</title></head>
                        <body class="bg-light d-flex align-items-center justify-content-center vh-100">
                        <div class="card shadow p-4 text-center" style="max-width: 500px;">
                            <h4 class="fw-bold">Lien temporaire (24h)</h4>
                            <input type="text" class="form-control font-monospace small mb-3" value="{temp_url}" readonly>
                            <a href="/" class="btn btn-secondary">Retour</a>
                        </div></body></html>""".encode('utf-8'))
                        return
            self.send_response(400)
            self.end_headers()
            return

        if parsed_url.path == "/delete":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                if target_path.startswith(UPLOAD_DIR):
                    if os.path.exists(target_path):
                        try:
                            trash_dest = os.path.join(TRASH_DIR, f"{uuid.uuid4()}_{os.path.basename(target_path)}")
                            shutil.move(target_path, trash_dest)
                            FILE_OWNERS.pop(rel_file, None)
                        except Exception:
                            pass
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        super().do_GET()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        if parsed_url.path == "/login":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            username = params.get("username", [""])[0].strip()
            password = params.get("password", [""])[0].strip()
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            if username in USERS_DB and USERS_DB[username]["password"] == hashed_password:
                session_id = str(uuid.uuid4())
                SESSIONS[session_id] = username
                self.send_response(303)
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/')
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.send_login_page(error="Identifiant ou mot de passe incorrect.")
            return

        logged_in_user = self.check_auth()
        if not logged_in_user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return

        user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")

        # Demande d'ami
        if parsed_url.path == "/add-friend":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            friend_target = params.get("friend_name", [""])[0].strip()

            if friend_target in USERS_DB and friend_target != logged_in_user:
                if friend_target not in PENDING_REQUESTS.setdefault(logged_in_user, []) and logged_in_user not in FRIENDS.get(friend_target, []):
                    PENDING_REQUESTS.setdefault(friend_target, []).append(logged_in_user)
                    log_event(f"Demande d'ami envoyée de {logged_in_user} à {friend_target}")
            
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        if parsed_url.path == "/create-folder":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            folder_name = params.get("folder_name", [""])[0].strip()
            current_folder = params.get("current_folder", [""])[0].strip()

            if folder_name:
                safe_name = "".join(c for c in folder_name if c.isalnum() or c in (' ', '_', '-')).strip()
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, current_folder, safe_name))
                if target_path.startswith(UPLOAD_DIR):
                    os.makedirs(target_path, exist_ok=True)
            self.send_response(303)
            self.send_header('Location', f'/{current_folder}')
            self.end_headers()
            return

        if parsed_url.path == "/save-file":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            rel_file = params.get("file", [""])[0].strip()
            file_content = params.get("content", [""])[0]

            if rel_file:
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                if target_path.startswith(UPLOAD_DIR) and os.path.isfile(target_path):
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write(file_content)
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        if parsed_url.path == "/create-note":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            note_name = params.get("note_name", [""])[0].strip()
            target_folder = params.get("target_folder", [logged_in_user])[0].strip()

            if note_name:
                if not note_name.endswith('.txt'):
                    note_name += '.txt'
                safe_name = "".join(c for c in note_name if c.isalnum() or c in (' ', '_', '-', '.')).strip()
                dest_dir = os.path.join(UPLOAD_DIR, target_folder)
                os.makedirs(dest_dir, exist_ok=True)
                filepath = os.path.join(dest_dir, safe_name)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("Nouvelle note...")
                rel_path = os.path.relpath(filepath, UPLOAD_DIR).replace('\\', '/')
                FILE_OWNERS[rel_path] = logged_in_user
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        if parsed_url.path == "/admin-action" and user_role == "admin":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            action = params.get("action", [""])[0]

            if action == "add_user":
                new_user = params.get("new_username", [""])[0].strip()
                new_pass = params.get("new_password", [""])[0].strip()
                new_role = params.get("new_role", ["user"])[0].strip()
                if new_user and new_pass:
                    USERS_DB[new_user] = {"password": hashlib.sha256(new_pass.encode('utf-8')).hexdigest(), "role": new_role}
                    os.makedirs(os.path.join(UPLOAD_DIR, new_user), exist_ok=True)
                    FRIENDS[new_user] = []
                    PENDING_REQUESTS[new_user] = []
                    save_users_to_file()
            elif action == "delete_user":
                del_user = params.get("del_username", [""])[0].strip()
                if del_user in USERS_DB and del_user != "admin":
                    USERS_DB.pop(del_user, None)
                    save_users_to_file()

            self.send_response(303)
            self.send_header('Location', '/admin')
            self.end_headers()
            return

        # Upload de fichier
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            self.send_response(400)
            self.end_headers()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            boundary = content_type.split("boundary=")[1].encode('utf-8')
            parts = body.split(boundary)
            target_subfolder = logged_in_user

            for part in parts:
                if b'name="target_folder"' in part:
                    header_part, val_data = part.split(b'\r\n\r\n', 1)
                    val_data = val_data.rstrip(b'\r\n--')
                    folder_val = val_data.decode('utf-8').strip()
                    if folder_val:
                        is_friend_folder = folder_val in FRIENDS.get(logged_in_user, [])
                        if user_role == "admin" or folder_val.lower() == "fichier commun" or folder_val == logged_in_user or is_friend_folder:
                            target_subfolder = folder_val

            destination_dir = os.path.join(UPLOAD_DIR, target_subfolder)
            os.makedirs(destination_dir, exist_ok=True)

            for part in parts:
                if b'filename="' in part:
                    header_part, file_data = part.split(b'\r\n\r\n', 1)
                    file_data = file_data.rstrip(b'\r\n--')
                    filename_start = header_part.find(b'filename="') + 10
                    filename_end = header_part.find(b'"', filename_start)
                    filename = header_part[filename_start:filename_end].decode('utf-8')
                    
                    if filename:
                        filename = os.path.basename(filename)
                        filepath = os.path.join(destination_dir, filename)
                        with open(filepath, "wb") as f:
                            f.write(file_data)
                        rel_path = os.path.relpath(filepath, UPLOAD_DIR).replace('\\', '/')
                        FILE_OWNERS[rel_path] = logged_in_user
        except Exception as e:
            log_event(f"Erreur upload : {e}")

        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

    def send_file_content(self, filepath):
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(filepath)}"')
        self.end_headers()
        with open(filepath, "rb") as f:
            shutil.copyfileobj(f, self.wfile)

    def send_forbidden(self, message):
        self.send_response(403)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Accès Interdit</title></head>
        <body class="bg-light d-flex align-items-center justify-content-center vh-100">
        <div class="card shadow p-4 text-center" style="max-width: 450px;">
            <h3 class="text-danger fw-bold">Accès Interdit (403)</h3>
            <p class="text-muted">{message}</p>
            <a href="/" class="btn btn-outline-primary mt-2">Retour</a>
        </div></body></html>""".encode('utf-8'))

    def send_login_page(self, error=""):
        html_page = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Connexion - Aresos Cloud</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet"></head>
        <body class="bg-dark d-flex align-items-center justify-content-center vh-100">
            <div class="card shadow-lg p-4 bg-secondary text-light" style="width: 100%; max-width: 400px; border-radius: 12px;">
                <div class="text-center mb-4">
                    <i class="bi bi-shield-lock-fill text-warning display-4"></i>
                    <h3 class="fw-bold mt-2">Connexion Aresos</h3>
                </div>
                {f'<div class="alert alert-danger py-2 small text-center">{error}</div>' if error else ''}
                <form action="/login" method="POST">
                    <div class="mb-3">
                        <label class="form-label small fw-semibold">Nom d'utilisateur</label>
                        <input type="text" name="username" class="form-control" required autofocus autocomplete="username">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small fw-semibold">Mot de passe</label>
                        <input type="password" name="password" class="form-control" required autocomplete="current-password">
                    </div>
                    <button type="submit" class="btn btn-warning w-100 fw-bold py-2 shadow-sm">Se connecter</button>
                </form>
            </div>
        </body></html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_page.encode("utf-8"))

    def send_edit_page(self, rel_file, filename, content):
        html_content = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Éditer - {filename}</title></head>
        <body class="bg-dark text-light p-4">
        <div class="container" style="max-width: 800px;">
            <h3 class="fw-bold mb-3">Éditer : {filename}</h3>
            <form action="/save-file" method="POST">
                <input type="hidden" name="file" value="{html.escape(rel_file)}">
                <div class="mb-3">
                    <textarea name="content" class="form-control bg-secondary text-light font-monospace" rows="15">{html.escape(content)}</textarea>
                </div>
                <div class="d-flex justify-content-between">
                    <a href="/" class="btn btn-outline-light">Annuler</a>
                    <button type="submit" class="btn btn-warning fw-bold px-4">Enregistrer</button>
                </div>
            </form>
        </div></body></html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def send_admin_dashboard(self, logged_in_user):
        logs = []
        if os.path.exists("server.log"):
            try:
                with open("server.log", "r", encoding="utf-8") as lf:
                    logs = lf.readlines()[-30:]
            except Exception:
                pass

        html_content = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Administration</title></head>
        <body class="bg-light">
        <nav class="navbar navbar-dark bg-dark shadow-sm mb-4">
            <div class="container">
                <a class="navbar-brand font-monospace fw-bold" href="/">Aresos Admin</a>
                <a href="/" class="btn btn-outline-light btn-sm">Retour au Cloud</a>
            </div>
        </nav>
        <div class="container pb-5">
            <div class="row g-4">
                <div class="col-md-6">
                    <div class="card shadow-sm h-100">
                        <div class="card-body">
                            <h4 class="card-title fw-bold mb-3">Utilisateurs</h4>
                            <ul class="list-group mb-3">"""
        for u, data in USERS_DB.items():
            html_content += f'<li class="list-group-item d-flex justify-content-between align-items-center"><span><b>{u}</b> ({data.get("role","user")})</span>'
            if u != "admin":
                html_content += f'<form action="/admin-action" method="POST" class="m-0"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="del_username" value="{u}"><button type="submit" class="btn btn-outline-danger btn-sm">Supprimer</button></form>'
            html_content += '</li>'

        html_content += """
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card shadow-sm h-100">
                        <div class="card-body">
                            <h4 class="card-title fw-bold mb-3">Logs du serveur</h4>
                            <div class="bg-dark text-light p-3 rounded font-monospace small" style="height: 350px; overflow-y: scroll;">"""
        for line in reversed(logs):
            html_content += f"<div>{html.escape(line.strip())}</div>"
        html_content += """
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div></body></html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def list_directory(self, path):
        try:
            all_items = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission")
            return None

        logged_in_user = self.check_auth() or "Visiteur"
        user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")

        rel_current = os.path.relpath(path, UPLOAD_DIR).replace('\\', '/')
        if rel_current == ".":
            rel_current = ""

        if user_role != "admin":
            if rel_current == "":
                list_dir = ["Fichier commun"]
                if os.path.exists(os.path.join(UPLOAD_DIR, logged_in_user)):
                    list_dir.append(logged_in_user)
                for friend in FRIENDS.get(logged_in_user, []):
                    if os.path.exists(os.path.join(UPLOAD_DIR, friend)):
                        list_dir.append(friend)
            else:
                first_folder = rel_current.split('/')[0]
                is_friend_folder = first_folder in FRIENDS.get(logged_in_user, [])
                if first_folder.lower() == "fichier commun" or first_folder == logged_in_user or is_friend_folder:
                    list_dir = all_items
                else:
                    self.send_forbidden("Accès refusé.")
                    return None
        else:
            hidden_items = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "server_secure_3.py", "lancement.bat", "server.log", ".corbeille"]
            list_dir = [item for item in all_items if item.lower() not in hidden_items]

        list_dir.sort(key=lambda a: (not os.path.isdir(os.path.join(path, a)), a.lower()))
        displaypath = html.escape(urllib.parse.unquote(self.path))

        my_notifications = PENDING_REQUESTS.get(logged_in_user, [])
        notif_count = len(my_notifications)
        my_friends = FRIENDS.get(logged_in_user, [])

        html_content = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Aresos Cloud</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            .drag-area {{ border: 2px dashed #0d6efd; border-radius: 8px; padding: 20px; text-align: center; background-color: #f8f9fa; cursor: pointer; }}
            .drag-area.active {{ background-color: #e2e6ea; }}
        </style></head>
        <body class="bg-light">
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm mb-4">
                <div class="container">
                    <a class="navbar-brand font-monospace fw-bold" href="/"><i class="bi bi-cloud-arrow-down-fill text-warning me-2"></i>Aresos Cloud</a>
                    <div class="d-flex align-items-center gap-3">
                        
                        <!-- LISTE DES AMIS -->
                        <div class="dropdown">
                            <button class="btn btn-outline-light btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="bi bi-people-fill text-warning me-1"></i> Amis ({len(my_friends)})
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end shadow" style="min-width: 220px;">
                                <li class="dropdown-header fw-bold">Mes amis</li>
                                <li><hr class="dropdown-divider"></li>"""
        
        if my_friends:
            for fr in my_friends:
                html_content += f'<li><span class="dropdown-item small"><i class="bi bi-person-check-fill text-success me-2"></i>{fr}</span></li>'
        else:
            html_content += '<li><span class="dropdown-item text-muted small text-center">Aucun ami pour le moment</span></li>'

        html_content += f"""
                            </ul>
                        </div>

                        <!-- CLOCHE DE NOTIFICATIONS -->
                        <div class="dropdown">
                            <button class="btn btn-dark position-relative dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="bi bi-bell-fill fs-5 text-warning"></i>
                                {f'<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">{notif_count}</span>' if notif_count > 0 else ''}
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end shadow" style="min-width: 280px;">
                                <li class="dropdown-header fw-bold">Demandes d'amis en attente</li>
                                <li><hr class="dropdown-divider"></li>"""
        
        if my_notifications:
            for friend in my_notifications:
                html_content += f"""
                <li class="px-3 py-1 d-flex justify-content-between align-items-center small">
                    <span><b>{friend}</b> veut être votre ami</span>
                    <a href="/accept-friend/{friend}" class="btn btn-success btn-sm py-0 px-2">Accepter</a>
                </li>"""
        else:
            html_content += '<li><span class="dropdown-item text-muted small text-center">Aucune nouvelle notification</span></li>'

        html_content += f"""
                            </ul>
                        </div>

                        <span class="text-light small"><i class="bi bi-person-circle me-1 text-warning"></i><b>{html.escape(logged_in_user)}</b></span>
                        {f'<a href="/admin" class="btn btn-outline-warning btn-sm">Admin</a>' if user_role == 'admin' else ''}
                        <a href="/logout" class="btn btn-outline-light btn-sm"><i class="bi bi-box-arrow-right me-1"></i></a>
                    </div>
                </div>
            </nav>
            <div class="container pb-5">
                
                <!-- Panneau d'actions et ajout d'amis -->
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <ul class="nav nav-tabs mb-3" id="uploadTab" role="tablist">
                            <li class="nav-item"><button class="nav-link active fw-semibold" id="file-tab" data-bs-toggle="tab" data-bs-target="#file-panel" type="button"><i class="bi bi-cloud-upload-fill text-primary me-1"></i> Envoyer</button></li>
                            <li class="nav-item"><button class="nav-link fw-semibold" id="friend-tab" data-bs-toggle="tab" data-bs-target="#friend-panel" type="button"><i class="bi bi-person-plus-fill text-success me-1"></i> Ajouter un ami</button></li>
                            <li class="nav-item"><button class="nav-link fw-semibold" id="folder-tab" data-bs-toggle="tab" data-bs-target="#folder-panel" type="button"><i class="bi bi-folder-plus text-warning me-1"></i> Dossier</button></li>
                            <li class="nav-item"><button class="nav-link fw-semibold" id="note-tab" data-bs-toggle="tab" data-bs-target="#note-panel" type="button"><i class="bi bi-file-earmark-text text-info me-1"></i> Note</button></li>
                        </ul>
                        
                        <div class="tab-content" id="uploadTabContent">
                            <!-- Envoi fichier -->
                            <div class="tab-pane fade show active" id="file-panel" role="tabpanel">
                                <form action="" method="POST" enctype="multipart/form-data" class="row g-3">
                                    <div class="col-md-4">
                                        <label class="form-label small fw-semibold">Destinataire</label>
                                        <select name="target_folder" class="form-select form-select-sm">
                                            <option value="Fichier commun">Fichier commun</option>
                                            <option value="{logged_in_user}">{logged_in_user} (Moi)</option>"""
        for f in FRIENDS.get(logged_in_user, []):
            html_content += f'<option value="{f}">{f} (Mon ami)</option>'
        html_content += f"""
                                        </select>
                                    </div>
                                    <div class="col-md-8">
                                        <input type="file" name="file" class="form-control form-control-sm mb-2" required>
                                        <div class="text-end"><button type="submit" class="btn btn-primary btn-sm px-4">Envoyer</button></div>
                                    </div>
                                </form>
                            </div>

                            <!-- Ajouter un ami avec liste déroulante -->
                            <div class="tab-pane fade" id="friend-panel" role="tabpanel">
                                <form action="/add-friend" method="POST" class="row g-3">
                                    <div class="col-md-8">
                                        <label class="form-label small fw-semibold">Sélectionner un utilisateur</label>
                                        <select name="friend_name" class="form-select form-select-sm" required>
                                            <option value="" disabled selected>-- Choisir un utilisateur --</option>"""
        
        for u in USERS_DB.keys():
            if u != logged_in_user and u != "admin" and u not in FRIENDS.get(logged_in_user, []):
                html_content += f'<option value="{u}">{u}</option>'

        html_content += f"""
                                        </select>
                                    </div>
                                    <div class="col-md-4 d-flex align-items-end">
                                        <button type="submit" class="btn btn-success btn-sm w-100 fw-semibold">Envoyer la demande</button>
                                    </div>
                                </form>
                            </div>

                            <!-- Dossier -->
                            <div class="tab-pane fade" id="folder-panel" role="tabpanel">
                                <form action="/create-folder" method="POST" class="row g-3">
                                    <input type="hidden" name="current_folder" value="{html.escape(rel_current)}">
                                    <div class="col-md-8"><input type="text" name="folder_name" class="form-control form-control-sm" placeholder="Nom du dossier" required></div>
                                    <div class="col-md-4"><button type="submit" class="btn btn-warning btn-sm w-100">Créer</button></div>
                                </form>
                            </div>

                            <!-- Note -->
                            <div class="tab-pane fade" id="note-panel" role="tabpanel">
                                <form action="/create-note" method="POST" class="row g-3">
                                    <div class="col-md-4">
                                        <select name="target_folder" class="form-select form-select-sm">
                                            <option value="Fichier commun">Fichier commun</option>
                                            <option value="{logged_in_user}">{logged_in_user}</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6"><input type="text" name="note_name" class="form-control form-control-sm" placeholder="Nom de la note.txt" required></div>
                                    <div class="col-md-2"><button type="submit" class="btn btn-info btn-sm w-100 text-white">Créer</button></div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Explorateur -->
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <h4 class="card-title fw-bold mb-3"><i class="bi bi-folder2-open me-2 text-warning"></i>Explorateur : <span class="text-muted font-monospace fs-6">{displaypath}</span></h4>"""
        
        if self.path != "/":
            path_parts = [p for p in self.path.split('/') if p]
            parent_path = "/" + "/".join(path_parts[:-1]) + "/" if len(path_parts) > 1 else "/"
            html_content += f'<p><a href="{parent_path}" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left me-1"></i>Dossier parent</a></p>'

        html_content += """
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead class="table-dark">
                                <tr><th>Nom</th><th>Type</th><th>Propriétaire</th><th class="text-end">Actions</th></tr>
                            </thead>
                            <tbody>"""

        for name in list_dir:
            fullname = os.path.join(path, name)
            is_dir = os.path.isdir(fullname)
            rel_path = os.path.relpath(fullname, UPLOAD_DIR).replace('\\', '/')
            icon = self.get_file_icon(name, is_dir)
            display_name = html.escape(name)
            owner = FILE_OWNERS.get(rel_path, "-")
            if is_dir:
                owner = "Partagé" if name.lower() == "fichier commun" else (name if name in USERS_DB else "Dossier")

            link = urllib.parse.quote(name) + ("/" if is_dir else "")
            
            html_content += f"""
                                <tr>
                                    <td><i class="bi {icon} me-2 fs-5"></i><a href="{link}" class="text-decoration-none fw-semibold text-dark">{display_name}</a></td>
                                    <td><span class="badge bg-light text-dark border">{'Dossier' if is_dir else 'Fichier'}</span></td>
                                    <td><span class="small text-muted">{owner}</span></td>
                                    <td class="text-end">"""
            if not is_dir:
                html_content += f'<a href="{link}" download class="btn btn-outline-success btn-sm me-1"><i class="bi bi-download"></i></a>'
            html_content += f'<a href="/delete?file={urllib.parse.quote(rel_path)}" class="btn btn-outline-danger btn-sm" onclick="return confirm(\'Supprimer ?\');"><i class="bi bi-trash"></i></a></td></tr>'

        html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        </body></html>"""

        response_bytes = html_content.encode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        if self.command == 'GET':
            self.wfile.write(response_bytes)
        return None

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, SecureHandler)
    log_event(f"[*] Serveur social & cloud lancé sur le port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event("[*] Arrêt du serveur.")
        httpd.server_close()
