import http.server
import os
import io
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

def format_size(size_bytes):
    if size_bytes == 0:
        return "-"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

USERS_DB = load_users()
SESSIONS = {}
FILE_OWNERS = {}
TEMP_LINKS = {}

UPLOAD_DIR = os.getcwd()
TRASH_DIR = os.path.join(UPLOAD_DIR, ".corbeille")
os.makedirs(TRASH_DIR, exist_ok=True)

COMMUN_DIR = os.path.join(UPLOAD_DIR, "Fichier commun")
os.makedirs(COMMUN_DIR, exist_ok=True)

for username in USERS_DB.keys():
    user_folder = os.path.join(UPLOAD_DIR, username)
    os.makedirs(user_folder, exist_ok=True)

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

        # Page d'administration dédiée (/admin)
        if parsed_url.path == "/admin":
            if user_role != "admin":
                self.send_forbidden("Accès réservé à l'administrateur.")
                return
            self.send_admin_dashboard(logged_in_user)
            return

        # Téléchargement d'un dossier en ZIP
        if parsed_url.path == "/download-zip":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "dir" in query_params:
                rel_dir = query_params["dir"][0]
                target_dir = os.path.normpath(os.path.join(UPLOAD_DIR, rel_dir))
                if target_dir.startswith(UPLOAD_DIR) and os.path.isdir(target_dir):
                    first_folder = rel_dir.split('/')[0] if '/' in rel_dir else rel_dir
                    if user_role == "admin" or first_folder.lower() == "fichier commun" or first_folder == logged_in_user:
                        zip_filename = f"{os.path.basename(target_dir) or 'cloud'}.zip"
                        zip_path = shutil.make_archive(os.path.join(UPLOAD_DIR, "temp_archive"), 'zip', target_dir)
                        self.send_response(200)
                        self.send_header("Content-type", "application/zip")
                        self.send_header("Content-Disposition", f'attachment; filename="{zip_filename}"')
                        self.end_headers()
                        with open(zip_path, 'rb') as zf:
                            shutil.copyfileobj(zf, self.wfile)
                        os.remove(zip_path)
                        log_event(f"Dossier {rel_dir} téléchargé en ZIP par {logged_in_user}")
                        return
            self.send_forbidden("Téléchargement du dossier refusé.")
            return

        # Édition ou prévisualisation d'un fichier texte
        if parsed_url.path == "/preview" or parsed_url.path == "/edit":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                if target_path.startswith(UPLOAD_DIR) and os.path.isfile(target_path):
                    first_folder = rel_file.split('/')[0] if '/' in rel_file else rel_file
                    if user_role == "admin" or first_folder.lower() == "fichier commun" or first_folder == logged_in_user:
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
            self.wfile.write(b"Fichier non trouve ou non modifiable.")
            return

        if parsed_url.path.startswith("/temp-download/"):
            token = parsed_url.path.split("/")[-1]
            if token in TEMP_LINKS:
                link_info = TEMP_LINKS[token]
                if datetime.datetime.now() < link_info["expires"]:
                    filepath = link_info["filepath"]
                    if os.path.exists(filepath):
                        log_event(f"Téléchargement par lien temporaire réussi : {os.path.basename(filepath)}")
                        self.send_file_content(filepath)
                        return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Lien temporaire invalide ou expire.")
            return

        if parsed_url.path == "/generate-link":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                if target_path.startswith(UPLOAD_DIR):
                    if user_role != "admin":
                        user_prefix = os.path.join(UPLOAD_DIR, logged_in_user)
                        commun_prefix = os.path.join(UPLOAD_DIR, "Fichier commun")
                        if not target_path.startswith(user_prefix) and not target_path.startswith(commun_prefix):
                            self.send_forbidden("Accès refusé à ce fichier.")
                            return
                    
                    if os.path.exists(target_path) and os.path.isfile(target_path):
                        token = str(uuid.uuid4())
                        expires = datetime.datetime.now() + datetime.timedelta(hours=24)
                        TEMP_LINKS[token] = {"filepath": target_path, "expires": expires}
                        
                        host = self.headers.get('Host', 'localhost:8000')
                        temp_url = f"https://{host}/temp-download/{token}" if 'onrender.com' in host else f"http://{host}/temp-download/{token}"
                        
                        self.send_response(200)
                        self.send_header("Content-type", "text/html; charset=utf-8")
                        self.end_headers()
                        self.wfile.write(f"""
                        <!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
                        <title>Lien Temporaire - Aresos</title></head>
                        <body class="bg-light d-flex align-items-center justify-content-center vh-100">
                        <div class="card shadow p-4 text-center" style="max-width: 500px;">
                            <i class="bi bi-link-45deg text-primary display-3 mb-3"></i>
                            <h4 class="fw-bold">Lien temporaire généré</h4>
                            <p class="text-muted small">Valide 24h pour : <b>{html.escape(rel_file)}</b></p>
                            <div class="input-group mb-3">
                                <input type="text" class="form-control font-monospace small" id="tempLink" value="{temp_url}" readonly>
                                <button class="btn btn-outline-primary" onclick="navigator.clipboard.writeText(document.getElementById('tempLink').value); alert('Lien copié !');">Copier</button>
                            </div>
                            <a href="/" class="btn btn-secondary mt-2">Retour à l'accueil</a>
                        </div></body></html>
                        """.encode('utf-8'))
                        return
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Fichier introuvable.")
            return

        # Suppression avec envoi dans la Corbeille
        if parsed_url.path == "/delete":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                
                if target_path.startswith(UPLOAD_DIR):
                    is_owner = FILE_OWNERS.get(rel_file) == logged_in_user
                    user_prefix = os.path.join(UPLOAD_DIR, logged_in_user)
                    commun_prefix = os.path.join(UPLOAD_DIR, "Fichier commun")
                    
                    if user_role == "admin" or is_owner or target_path.startswith(user_prefix) or target_path.startswith(commun_prefix):
                        protected = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "server_secure_3.py", "lancement.bat", "server.log"]
                        if os.path.basename(target_path).lower() not in protected and os.path.exists(target_path):
                            try:
                                trash_dest = os.path.join(TRASH_DIR, f"{uuid.uuid4()}_{os.path.basename(target_path)}")
                                shutil.move(target_path, trash_dest)
                                FILE_OWNERS.pop(rel_file, None)
                                log_event(f"Élément mis à la corbeille : {rel_file} par {logged_in_user}")
                            except Exception as e:
                                log_event(f"Erreur mise à la corbeille {rel_file} : {e}")
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        path_decoded = urllib.parse.unquote(parsed_url.path).lstrip('/')
        fichiers_sensibles = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "server_secure_3.py", "lancement.bat", "server.log"]
        
        if path_decoded.lower() in fichiers_sensibles and user_role != "admin":
            self.send_forbidden("Accès refusé.")
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
                log_event(f"Connexion réussie : {username}")
                self.send_response(303)
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/')
                self.send_header('Location', '/')
                self.end_headers()
            else:
                log_event(f"Échec de connexion : {username}")
                self.send_login_page(error="Identifiant ou mot de passe incorrect.")
            return

        logged_in_user = self.check_auth()
        if not logged_in_user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return

        user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")

        # Création d'un sous-dossier
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
                    log_event(f"Dossier créé : {safe_name} par {logged_in_user}")
            self.send_response(303)
            self.send_header('Location', f'/{current_folder}')
            self.end_headers()
            return

        # Sauvegarde d'une note ou d'un fichier édité
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
                    log_event(f"Fichier modifié/enregistré : {rel_file} par {logged_in_user}")
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        # Création d'une nouvelle note texte
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
                log_event(f"Note créée : {safe_name} par {logged_in_user}")
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        # Gestion Admin : Ajout / Suppression d'utilisateurs
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
                    save_users_to_file()
                    log_event(f"Admin a créé l'utilisateur : {new_user}")
            elif action == "delete_user":
                del_user = params.get("del_username", [""])[0].strip()
                if del_user in USERS_DB and del_user != "admin":
                    USERS_DB.pop(del_user, None)
                    save_users_to_file()
                    log_event(f"Admin a supprimé l'utilisateur : {del_user}")

            self.send_response(303)
            self.send_header('Location', '/admin')
            self.end_headers()
            return

        # Ajout d'un lien externe
        if parsed_url.path == "/add-link":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            link_title = params.get("link_title", [""])[0].strip()
            link_url = params.get("link_url", [""])[0].strip()
            target_folder = params.get("target_folder", [logged_in_user])[0].strip()
            
            if link_title and link_url:
                safe_title = "".join(c for c in link_title if c.isalnum() or c in (' ', '_', '-')).rstrip()
                filename = f"{safe_title}.url"
                destination_dir = os.path.join(UPLOAD_DIR, target_folder)
                os.makedirs(destination_dir, exist_ok=True)
                filepath = os.path.join(destination_dir, filename)
                with open(filepath, "w", encoding="utf-8") as uf:
                    uf.write(f"[InternetShortcut]\nURL={link_url}\n")
                rel_path = os.path.relpath(filepath, UPLOAD_DIR).replace('\\', '/')
                FILE_OWNERS[rel_path] = logged_in_user
                log_event(f"Lien externe ajouté : {link_title} par {logged_in_user}")

            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        # Upload de fichier classique
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Requete invalide.")
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
                        if user_role == "admin" or folder_val.lower() == "fichier commun" or folder_val in USERS_DB:
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
                        log_event(f"Upload réussi : {filename} par {logged_in_user} dans {target_subfolder}")
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
        self.wfile.write(f"""
        <!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        <title>Accès Interdit - Aresos</title></head>
        <body class="bg-light d-flex align-items-center justify-content-center vh-100">
        <div class="card shadow p-4 text-center" style="max-width: 450px;">
            <i class="bi bi-shield-exclamation text-danger display-3 mb-3"></i>
            <h3 class="text-danger fw-bold">Accès Interdit (403)</h3>
            <p class="text-muted">{message}</p>
            <a href="/" class="btn btn-outline-primary mt-2">Retour à l'accueil</a>
        </div></body></html>
        """.encode('utf-8'))

    def send_edit_page(self, rel_file, filename, content):
        html_content = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        <title>Éditer - {filename}</title></head>
        <body class="bg-dark text-light p-4">
        <div class="container" style="max-width: 800px;">
            <h3 class="fw-bold mb-3"><i class="bi bi-pencil-square text-warning me-2"></i>Éditer : {filename}</h3>
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
                    logs = lf.readlines()[-30:] # Dernières 30 lignes
            except Exception:
                pass

        html_content = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        <title>Administration - Aresos Cloud</title></head>
        <body class="bg-light">
        <nav class="navbar navbar-dark bg-dark shadow-sm mb-4">
            <div class="container">
                <a class="navbar-brand font-monospace fw-bold" href="/"><i class="bi bi-shield-fill-check text-warning me-2"></i>Aresos Admin</a>
                <a href="/" class="btn btn-outline-light btn-sm"><i class="bi bi-house me-1"></i>Retour au Cloud</a>
            </div>
        </nav>
        <div class="container pb-5">
            <div class="row g-4">
                <div class="col-md-6">
                    <div class="card shadow-sm h-100">
                        <div class="card-body">
                            <h4 class="card-title fw-bold mb-3"><i class="bi bi-people-fill text-primary me-2"></i>Gestion des utilisateurs</h4>
                            <ul class="list-group mb-3">"""
        for u, data in USERS_DB.items():
            html_content += f'<li class="list-group-item d-flex justify-content-between align-items-center"><span><b>{u}</b> <span class="badge bg-secondary ms-2">{data["role"]}</span></span>'
            if u != "admin":
                html_content += f'<form action="/admin-action" method="POST" class="m-0"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="del_username" value="{u}"><button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-trash"></i></button></form>'
            html_content += '</li>'

        html_content += """
                            </ul>
                            <h5 class="fw-semibold mt-4">Ajouter un utilisateur</h5>
                            <form action="/admin-action" method="POST" class="row g-2">
                                <input type="hidden" name="action" value="add_user">
                                <div class="col-12"><input type="text" name="new_username" class="form-control form-control-sm" placeholder="Nom d'utilisateur" required></div>
                                <div class="col-12"><input type="password" name="new_password" class="form-control form-control-sm" placeholder="Mot de passe" required></div>
                                <div class="col-12">
                                    <select name="new_role" class="form-select form-select-sm">
                                        <option value="user">Utilisateur (user)</option>
                                        <option value="admin">Administrateur (admin)</option>
                                    </select>
                                </div>
                                <div class="col-12 text-end"><button type="submit" class="btn btn-primary btn-sm px-4">Créer le compte</button></div>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card shadow-sm h-100">
                        <div class="card-body">
                            <h4 class="card-title fw-bold mb-3"><i class="bi bi-journal-text text-warning me-2"></i>Logs du serveur en direct</h4>
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

    def send_login_page(self, error=""):
        html_content = f"""
        <!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Connexion - Aresos Cloud</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet"></head>
        <body class="bg-dark d-flex align-items-center justify-content-center vh-100">
            <div class="card shadow-lg p-4 bg-secondary text-light" style="width: 100%; max-width: 400px; border-radius: 12px;">
                <div class="text-center mb-4">
                    <i class="bi bi-shield-lock-fill text-warning display-4"></i>
                    <h3 class="fw-bold mt-2">Connexion Aresos</h3>
                    <p class="text-light small">Veuillez vous identifier pour accéder au cloud</p>
                </div>
                {f'<div class="alert alert-danger py-2 small text-center"><i class="bi bi-exclamation-triangle-fill me-1"></i>{error}</div>' if error else ''}
                <form action="/login" method="POST">
                    <div class="mb-3">
                        <label class="form-label fw-semibold"><i class="bi bi-person-fill me-1"></i> Nom d'utilisateur</label>
                        <input type="text" name="username" class="form-control" required autofocus autocomplete="username">
                    </div>
                    <div class="mb-3">
                        <label class="form-label fw-semibold"><i class="bi bi-key-fill me-1"></i> Mot de passe</label>
                        <div class="input-group">
                            <input type="password" name="password" id="passwordInput" class="form-control" required autocomplete="current-password">
                            <button class="btn btn-outline-light" type="button" id="togglePassword"><i class="bi bi-eye" id="toggleIcon"></i></button>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-warning w-100 fw-bold py-2 shadow-sm mt-2"><i class="bi bi-box-arrow-in-right me-1"></i> Se connecter</button>
                </form>
            </div>
            <script>
                document.querySelector('#togglePassword').addEventListener('click', function () {{
                    const pi = document.querySelector('#passwordInput');
                    const ti = document.querySelector('#toggleIcon');
                    const type = pi.getAttribute('type') === 'password' ? 'text' : 'password';
                    pi.setAttribute('type', type);
                    ti.classList.toggle('bi-eye'); ti.classList.toggle('bi-eye-slash');
                }});
            </script>
        </body></html>"""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def list_directory(self, path):
        try:
            all_items = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
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
            else:
                if rel_current.lower() == "fichier commun" or rel_current.startswith(logged_in_user):
                    list_dir = all_items
                else:
                    self.send_forbidden("Accès refusé.")
                    return None
        else:
            hidden_items = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "server_secure_3.py", "lancement.bat", "server.log", ".corbeille"]
            list_dir = [item for item in all_items if item.lower() not in hidden_items]

        list_dir.sort(key=lambda a: (not os.path.isdir(os.path.join(path, a)), a.lower()))
        displaypath = html.escape(urllib.parse.unquote(self.path))

        # Récupération des derniers logs pour le journal d'activité (Fonctionnalité 5)
        recent_logs = []
        if os.path.exists("server.log"):
            try:
                with open("server.log", "r", encoding="utf-8") as lf:
                    recent_logs = [line.strip() for line in lf.readlines()[-5:]]
            except Exception:
                pass

        html_content = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Echange de Fichiers - {displaypath}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            .drag-area {{ border: 2px dashed #0d6efd; border-radius: 8px; padding: 20px; text-align: center; background-color: #f8f9fa; cursor: pointer; transition: background-color 0.2s ease; }}
            .drag-area.active {{ background-color: #e2e6ea; }}
        </style></head>
        <body class="bg-light">
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm mb-4">
                <div class="container">
                    <a class="navbar-brand font-monospace fw-bold" href="/"><i class="bi bi-cloud-arrow-down-fill text-warning me-2"></i>Aresos Cloud</a>
                    <div class="d-flex align-items-center gap-3">
                        <span class="text-light small"><i class="bi bi-person-circle me-1 text-warning"></i><b>{html.escape(logged_in_user)}</b> ({html.escape(user_role)})</span>
                        {f'<a href="/admin" class="btn btn-outline-warning btn-sm"><i class="bi bi-shield-fill-gear me-1"></i>Admin</a>' if user_role == 'admin' else ''}
                        <a href="/logout" class="btn btn-outline-light btn-sm"><i class="bi bi-box-arrow-right me-1"></i>Déconnexion</a>
                    </div>
                </div>
            </nav>
            <div class="container pb-5">
                <!-- Zone d'envoi et de création -->
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <ul class="nav nav-tabs mb-3" id="uploadTab" role="tablist">
                            <li class="nav-item"><button class="nav-link active fw-semibold" id="file-tab" data-bs-toggle="tab" data-bs-target="#file-panel" type="button"><i class="bi bi-cloud-upload-fill text-primary me-1"></i> Envoyer un fichier</button></li>
                            <li class="nav-item"><button class="nav-link fw-semibold" id="folder-tab" data-bs-toggle="tab" data-bs-target="#folder-panel" type="button"><i class="bi bi-folder-plus text-warning me-1"></i> Créer un dossier</button></li>
                            <li class="nav-item"><button class="nav-link fw-semibold" id="note-tab" data-bs-toggle="tab" data-bs-target="#note-panel" type="button"><i class="bi bi-file-earmark-text text-success me-1"></i> Créer une note</button></li>
                            <li class="nav-item"><button class="nav-link fw-semibold" id="link-tab" data-bs-toggle="tab" data-bs-target="#link-panel" type="button"><i class="bi bi-link-45deg text-info me-1"></i> Lien externe</button></li>
                        </ul>
                        
                        <div class="tab-content" id="uploadTabContent">
                            <!-- Fichier -->
                            <div class="tab-pane fade show active" id="file-panel" role="tabpanel">
                                <form id="uploadForm" action="" method="POST" enctype="multipart/form-data" class="row g-3">
                                    <div class="col-md-4">
                                        <label class="form-label small fw-semibold">Dossier destinataire</label>
                                        <select name="target_folder" class="form-select form-select-sm">
                                            <option value="Fichier commun">Fichier commun</option>"""
        for u in USERS_DB.keys():
            selected = "selected" if u.lower() == logged_in_user.lower() else ""
            html_content += f'<option value="{u}" {selected}>{u}</option>'

        html_content += f"""
                                        </select>
                                    </div>
                                    <div class="col-md-8">
                                        <div class="drag-area" id="dragArea">
                                            <i class="bi bi-file-earmark-arrow-up display-6 text-primary mb-1"></i>
                                            <p class="mb-1 small">Glissez-déposez ou cliquez pour choisir</p>
                                            <input type="file" name="file" id="fileInput" class="d-none" required>
                                            <button type="button" class="btn btn-outline-primary btn-sm mt-1" onclick="document.getElementById('fileInput').click();">Parcourir</button>
                                        </div>
                                        <div class="text-end mt-2"><button type="submit" class="btn btn-primary btn-sm px-4">Envoyer</button></div>
                                    </div>
                                </form>
                            </div>

                            <!-- Créer un dossier (Fonctionnalité 1) -->
                            <div class="tab-pane fade" id="folder-panel" role="tabpanel">
                                <form action="/create-folder" method="POST" class="row g-3">
                                    <input type="hidden" name="current_folder" value="{html.escape(rel_current)}">
                                    <div class="col-md-8">
                                        <label class="form-label small fw-semibold">Nom du sous-dossier</label>
                                        <input type="text" name="folder_name" class="form-control form-control-sm" placeholder="Ex: Projets_2026" required>
                                    </div>
                                    <div class="col-md-4 d-flex align-items-end">
                                        <button type="submit" class="btn btn-warning btn-sm w-100 fw-semibold">Créer le dossier</button>
                                    </div>
                                </form>
                            </div>

                            <!-- Créer une note (Fonctionnalité 2) -->
                            <div class="tab-pane fade" id="note-panel" role="tabpanel">
                                <form action="/create-note" method="POST" class="row g-3">
                                    <div class="col-md-4">
                                        <label class="form-label small fw-semibold">Dossier destinataire</label>
                                        <select name="target_folder" class="form-select form-select-sm">
                                            <option value="Fichier commun">Fichier commun</option>"""
        for u in USERS_DB.keys():
            selected = "selected" if u.lower() == logged_in_user.lower() else ""
            html_content += f'<option value="{u}" {selected}>{u}</option>'

        html_content += f"""
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label small fw-semibold">Nom de la note</label>
                                        <input type="text" name="note_name" class="form-control form-control-sm" placeholder="Ex: Ma_To_Do_List.txt" required>
                                    </div>
                                    <div class="col-md-2 d-flex align-items-end">
                                        <button type="submit" class="btn btn-success btn-sm w-100 fw-semibold">Créer</button>
                                    </div>
                                </form>
                            </div>

                            <!-- Lien externe -->
                            <div class="tab-pane fade" id="link-panel" role="tabpanel">
                                <form action="/add-link" method="POST" class="row g-3">
                                    <div class="col-md-4">
                                        <label class="form-label small fw-semibold">Dossier destinataire</label>
                                        <select name="target_folder" class="form-select form-select-sm">
                                            <option value="Fichier commun">Fichier commun</option>"""
        for u in USERS_DB.keys():
            selected = "selected" if u.lower() == logged_in_user.lower() else ""
            html_content += f'<option value="{u}" {selected}>{u}</option>'

        html_content += f"""
                                        </select>
                                    </div>
                                    <div class="col-md-4">
                                        <label class="form-label small fw-semibold">Titre</label>
                                        <input type="text" name="link_title" class="form-control form-control-sm" placeholder="Ex: Drive Partagé" required>
                                    </div>
                                    <div class="col-md-4">
                                        <label class="form-label small fw-semibold">URL</label>
                                        <input type="url" name="link_url" class="form-control form-control-sm" placeholder="https://..." required>
                                    </div>
                                    <div class="col-12 text-end"><button type="submit" class="btn btn-info btn-sm px-4 text-white">Publier</button></div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Message d'avertissement -->
                <div class="alert alert-danger text-center fw-bold shadow-sm py-2 mb-4" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i> Attention : Les fichiers locaux sont éphémères. Sauvegardez vos gros fichiers sur <u>Google Drive</u> ou <u>Mega</u> !
                </div>

                <!-- Fil d'actualité en direct (Fonctionnalité 5) -->
                <div class="card shadow-sm mb-4 border-info">
                    <div class="card-body py-2 bg-light text-muted small d-flex align-items-center">
                        <i class="bi bi-bell-fill text-info me-2 fs-5"></i>
                        <div class="text-truncate font-monospace"><b>Dernière activité :</b> {html.escape(recent_logs[-1] if recent_logs else 'Aucune activité récente')}</div>
                    </div>
                </div>

                <!-- Explorateur -->
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
                            <h4 class="card-title fw-bold m-0"><i class="bi bi-folder2-open me-2 text-warning"></i>Explorateur : <span class="text-muted font-monospace fs-6">{displaypath}</span></h4>
                            <div class="input-group input-group-sm" style="max-width: 300px;">
                                <span class="input-group-text bg-white"><i class="bi bi-search text-muted"></i></span>
                                <input type="text" id="searchInput" class="form-control" placeholder="Rechercher...">
                            </div>
                        </div>"""

        html_content += f"""
        <div class="d-flex justify-content-between flex-wrap gap-2 mb-3">"""
        if self.path != "/":
            path_parts = [p for p in self.path.split('/') if p]
            parent_path = "/" + "/".join(path_parts[:-1]) + "/" if len(path_parts) > 1 else "/"
            html_content += f'<a href="{parent_path}" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left me-1"></i>Dossier parent</a>'
        else:
            html_content += '<div></div>'

        html_content += f"""
            <div class="d-flex gap-2">
                <a href="{EXTERNAL_CLOUD_LINK}" target="_blank" class="btn btn-outline-success btn-sm"><i class="bi bi-cloud-plus-fill me-1"></i> Drive / Mega</a>
                <a href="/download-zip?dir={urllib.parse.quote(rel_current)}" class="btn btn-outline-dark btn-sm"><i class="bi bi-file-earmark-zip-fill text-warning me-1"></i>Télécharger (ZIP)</a>
            </div>
        </div>"""

        html_content += """
                    <div class="table-responsive">
                        <table class="table table-hover align-middle" id="fileTable">
                            <thead class="table-dark">
                                <tr>
                                    <th>Nom</th>
                                    <th>Type</th>
                                    <th>Taille</th>
                                    <th>Modifié le</th>
                                    <th>Propriétaire</th>
                                    <th class="text-end">Actions</th>
                                </tr>
                            </thead>
                            <tbody>"""

        for name in list_dir:
            fullname = os.path.join(path, name)
            is_dir = os.path.isdir(fullname)
            rel_path = os.path.relpath(fullname, UPLOAD_DIR).replace('\\', '/')
            
            try:
                stat_info = os.stat(fullname)
                size_str = format_size(stat_info.st_size) if not is_dir else "-"
                mtime_str = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
            except Exception:
                size_str = "-"
                mtime_str = "-"

            icon = self.get_file_icon(name, is_dir)
            display_name = html.escape(name)
            owner = FILE_OWNERS.get(rel_path, "-")
            if is_dir:
                owner = "Partagé" if name.lower() == "fichier commun" else (name if name in USERS_DB else "Système")

            ext = os.path.splitext(name)[1].lower()
            if is_dir:
                link = urllib.parse.quote(name) + "/"
                type_str = "Dossier partagé" if name.lower() == "fichier commun" else ("Dossier" if name in USERS_DB else "Sous-dossier")
            elif ext == '.url':
                link = urllib.parse.quote(name)
                type_str = "Lien Externe"
            else:
                link = urllib.parse.quote(name)
                type_str = "Fichier"

            html_content += f"""
                                <tr class="file-row">
                                    <td class="file-name"><i class="bi {icon} me-2 fs-5"></i><a href="{link}" {"target='_blank'" if ext == '.url' else ''} class="text-decoration-none fw-semibold text-dark">{display_name}</a></td>
                                    <td><span class="badge bg-light text-dark border">{type_str}</span></td>
                                    <td class="small text-muted">{size_str}</td>
                                    <td class="small text-muted">{mtime_str}</td>
                                    <td><span class="small text-muted">{owner}</span></td>
                                    <td class="text-end">"""

            if not is_dir and ext != '.url':
                if ext in ['.txt', '.py', '.js', '.css', '.html', '.json', '.md']:
                    html_content += f'<a href="/edit?file={urllib.parse.quote(rel_path)}" class="btn btn-outline-warning btn-sm me-1" title="Modifier"><i class="bi bi-pencil-square"></i></a>'
                if ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.pdf', '.txt', '.py', '.js', '.css', '.html', '.json', '.md']:
                    html_content += f'<button onclick="openPreview(\'/preview?file={urllib.parse.quote(rel_path)}\')" class="btn btn-outline-primary btn-sm me-1" title="Aperçu"><i class="bi bi-eye"></i></button>'
                html_content += f'<a href="/generate-link?file={urllib.parse.quote(rel_path)}" class="btn btn-outline-info btn-sm me-1" title="Partage 24h"><i class="bi bi-share"></i></a>'
                html_content += f'<a href="{link}" download class="btn btn-outline-success btn-sm me-1" title="Télécharger"><i class="bi bi-download"></i></a>'

            can_delete = user_role == "admin" or owner == logged_in_user or rel_path.startswith("Fichier commun")
            if can_delete and name.lower() not in ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "server_secure_3.py", "lancement.bat", "fichier commun"]:
                html_content += f'<a href="/delete?file={urllib.parse.quote(rel_path)}" class="btn btn-outline-danger btn-sm" onclick="return confirm(\'Mettre à la corbeille ?\');" title="Supprimer"><i class="bi bi-trash"></i></a>'

            html_content += """
                                    </td>
                                </tr>"""

        html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Modal Aperçu -->
        <div class="modal fade" id="previewModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-xl modal-dialog-centered">
                <div class="modal-content bg-dark text-light">
                    <div class="modal-header border-secondary">
                        <h5 class="modal-title"><i class="bi bi-eye me-2"></i>Aperçu</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body p-0" style="min-height: 500px;">
                        <iframe id="previewFrame" src="" style="width:100%; height:600px; border:none;"></iframe>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.getElementById('searchInput').addEventListener('keyup', function() {
                const filter = this.value.toLowerCase();
                document.querySelectorAll('#fileTable .file-row').forEach(row => {
                    const text = row.querySelector('.file-name').textContent.toLowerCase();
                    row.style.display = text.includes(filter) ? '' : 'none';
                });
            });
            function openPreview(url) {
                document.getElementById('previewFrame').src = url;
                new bootstrap.Modal(document.getElementById('previewModal')).show();
            }
            const dragArea = document.getElementById('dragArea');
            const fileInput = document.getElementById('fileInput');
            if(dragArea && fileInput) {
                ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => dragArea.addEventListener(e, ev => { ev.preventDefault(); ev.stopPropagation(); }, false));
                ['dragenter', 'dragover'].forEach(e => dragArea.addEventListener(e, () => dragArea.classList.add('active'), false));
                ['dragleave', 'drop'].forEach(e => dragArea.addEventListener(e, () => dragArea.classList.remove('active'), false));
                dragArea.addEventListener('drop', e => {
                    fileInput.files = e.dataTransfer.files;
                    if(fileInput.files.length > 0) dragArea.querySelector('p').textContent = "Fichier : " + fileInput.files[0].name;
                });
                fileInput.addEventListener('change', function() {
                    if(this.files.length > 0) dragArea.querySelector('p').textContent = "Fichier : " + this.files[0].name;
                });
            }
        </script>
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
    log_event(f"[*] Serveur ultra-complet lancé sur le port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event("[*] Arrêt du serveur.")
        httpd.server_close()
