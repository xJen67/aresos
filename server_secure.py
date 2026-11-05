import http.server
import os
import io
import urllib.parse
import html
import shutil
import uuid
import datetime
from http import cookies

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
                        current_pass = val
                    elif key == "role":
                        current_role = val.lower()
                
                if current_user and current_pass:
                    users_db[current_user] = {"password": current_pass, "role": current_role}
                        
            log_event(f"[*] Fichier '{filename}' lu avec succès ! Comptes chargés : {list(users_db.keys())}")
        except Exception as e:
            log_event(f"[!] Erreur lors de la lecture du fichier : {e}")
    else:
        log_event(f"[!] Fichier '{filename}' introuvable. Compte de secours 'admin':'admin'")
        users_db["admin"] = {"password": "admin", "role": "admin"}
        
    return users_db

USERS_DB = load_users()
SESSIONS = {}  # session_id -> username
FILE_OWNERS = {} # filename (relative path) -> username
TEMP_LINKS = {} # token -> {"filepath": ..., "expires": ...}

UPLOAD_DIR = os.path.join(os.getcwd(), "Echange de fichiers")
os.makedirs(UPLOAD_DIR, exist_ok=True)

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

    def get_file_icon(self, filename, is_dir):
        if is_dir:
            return "bi-folder-fill text-warning"
        ext = os.path.splitext(filename)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp']:
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
            log_event(f"ALERTE lien temporaire invalide ou expiré : {token} par {logged_in_user}")
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
                        if not target_path.startswith(user_prefix):
                            log_event(f"ALERTE 403 : {logged_in_user} a tenté de générer un lien pour {rel_file}")
                            self.send_forbidden("Accès refusé à ce fichier.")
                            return
                    
                    if os.path.exists(target_path) and os.path.isfile(target_path):
                        token = str(uuid.uuid4())
                        expires = datetime.datetime.now() + datetime.timedelta(hours=24)
                        TEMP_LINKS[token] = {"filepath": target_path, "expires": expires}
                        log_event(f"Lien temporaire généré par {logged_in_user} pour {rel_file}")
                        
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
                            <p class="text-muted small">Ce lien est valide pendant 24 heures pour le fichier : <b>{html.escape(rel_file)}</b></p>
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

        if parsed_url.path == "/delete":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                rel_file = query_params["file"][0]
                target_path = os.path.normpath(os.path.join(UPLOAD_DIR, rel_file))
                
                if target_path.startswith(UPLOAD_DIR):
                    is_owner = FILE_OWNERS.get(rel_file) == logged_in_user
                    user_prefix = os.path.join(UPLOAD_DIR, logged_in_user)
                    is_in_user_dir = target_path.startswith(user_prefix)
                    
                    if user_role == "admin" or is_owner or is_in_user_dir:
                        protected_files = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "lancement.bat"]
                        if os.path.basename(target_path).lower() not in protected_files and os.path.exists(target_path):
                            try:
                                if os.path.isdir(target_path):
                                    shutil.rmtree(target_path)
                                else:
                                    os.remove(target_path)
                                FILE_OWNERS.pop(rel_file, None)
                                log_event(f"Suppression réussie : {rel_file} par {logged_in_user}")
                            except Exception as e:
                                log_event(f"Erreur suppression {rel_file} : {e}")
                    else:
                        log_event(f"ALERTE 403 : {logged_in_user} a tenté de supprimer {rel_file}")
                        self.send_forbidden("Vous n'êtes pas autorisé à supprimer ce fichier.")
                        return

            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        path_decoded = urllib.parse.unquote(parsed_url.path).lstrip('/')
        fichiers_sensibles = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "lancement.bat", "server.log"]
        
        if path_decoded.lower() in fichiers_sensibles and user_role != "admin":
            log_event(f"ALERTE 403 : {logged_in_user} a tenté d'accéder au fichier sensible {path_decoded}")
            self.send_forbidden("Accès refusé : fichier réservé à l'administrateur.")
            return

        if path_decoded:
            parts_path = path_decoded.split('/')
            first_folder = parts_path[0]
            if first_folder in USERS_DB and user_role != "admin" and first_folder != logged_in_user:
                log_event(f"ALERTE 403 : {logged_in_user} a tenté d'accéder au dossier de {first_folder}")
                self.send_forbidden("Accès refusé à ce dossier personnel.")
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
            
            if username in USERS_DB and USERS_DB[username]["password"] == password:
                session_id = str(uuid.uuid4())
                SESSIONS[session_id] = username
                log_event(f"Succès de connexion : {username}")

                self.send_response(303)
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/')
                self.send_header('Location', '/')
                self.end_headers()
            else:
                log_event(f"Échec de connexion (mauvais identifiant/mdp) pour : {username}")
                self.send_login_page(error="Identifiant ou mot de passe incorrect.")
            return

        logged_in_user = self.check_auth()
        if not logged_in_user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return

        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            self.send_response(400)
            self.end_headers()
            self.wfile.write("Requête invalide.".encode('utf-8'))
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            boundary = content_type.split("boundary=")[1].encode('utf-8')
            parts = body.split(boundary)
            
            target_subfolder = logged_in_user
            user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")

            for part in parts:
                if b'name="target_folder"' in part:
                    header_part, val_data = part.split(b'\r\n\r\n', 1)
                    val_data = val_data.rstrip(b'\r\n--')
                    folder_val = val_data.decode('utf-8').strip()
                    if folder_val:
                        if user_role == "admin" or folder_val == logged_in_user:
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
                        log_event(f"Succès upload : {filename} par {logged_in_user} dans {target_subfolder}")
        except Exception as e:
            log_event(f"Erreur lors de l'upload par {logged_in_user} : {e}")

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

    def send_login_page(self, error=""):
        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Connexion - Aresos Cloud</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        </head>
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
                            <button class="btn btn-outline-light" type="button" id="togglePassword">
                                <i class="bi bi-eye" id="toggleIcon"></i>
                            </button>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-warning w-100 fw-bold py-2 shadow-sm mt-2">
                        <i class="bi bi-box-arrow-in-right me-1"></i> Se connecter
                    </button>
                </form>
            </div>
            <script>
                const togglePassword = document.querySelector('#togglePassword');
                const passwordInput = document.querySelector('#passwordInput');
                const toggleIcon = document.querySelector('#toggleIcon');
                
                togglePassword.addEventListener('click', function () {{
                    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                    passwordInput.setAttribute('type', type);
                    toggleIcon.classList.toggle('bi-eye');
                    toggleIcon.classList.toggle('bi-eye-slash');
                }});
            </script>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def list_directory(self, path):
        try:
            list_dir = os.listdir(path)
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
                list_dir = [logged_in_user] if os.path.exists(os.path.join(UPLOAD_DIR, logged_in_user)) else []
            else:
                if not rel_current.startswith(logged_in_user):
                    self.send_forbidden("Accès refusé.")
                    return None

        list_dir.sort(key=lambda a: (not os.path.isdir(os.path.join(path, a)), a.lower()))
        displaypath = html.escape(urllib.parse.unquote(self.path))

        html_content = f"""<!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Echange de Fichiers - {displaypath}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm mb-4">
                <div class="container">
                    <a class="navbar-brand font-monospace fw-bold" href="/"><i class="bi bi-cloud-arrow-down-fill text-warning me-2"></i>Aresos Cloud</a>
                    <div class="d-flex align-items-center gap-3">
                        <span class="text-light small"><i class="bi bi-person-circle me-1 text-warning"></i><b>{html.escape(logged_in_user)}</b> ({html.escape(user_role)})</span>
                        <a href="/logout" class="btn btn-outline-light btn-sm"><i class="bi bi-box-arrow-right me-1"></i>Déconnexion</a>
                    </div>
                </div>
            </nav>
            <div class="container pb-5">
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        <h5 class="card-title fw-bold mb-3"><i class="bi bi-cloud-upload-fill text-primary me-2"></i>Mettre en ligne un fichier</h5>
                        <form action="" method="POST" enctype="multipart/form-data" class="row g-3">"""

        if user_role == "admin":
            html_content += f"""
                            <div class="col-md-4">
                                <label class="form-label small fw-semibold">Dossier destinataire</label>
                                <select name="target_folder" class="form-select form-select-sm">"""
            for u in USERS_DB.keys():
                html_content += f'<option value="{u}">{u}</option>'
            html_content += """
                                </select>
                            </div>
                            <div class="col-md-8">"""
        else:
            html_content += f'<input type="hidden" name="target_folder" value="{logged_in_user}">'
            html_content += '<div class="col-12">'

        html_content += """
                            <label class="form-label small fw-semibold">Sélectionner le fichier</label>
                            <div class="input-group">
                                <input type="file" name="file" class="form-control form-control-sm" required>
                                <button type="submit" class="btn btn-primary btn-sm px-4"><i class="bi bi-upload me-1"></i>Envoyer</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <div class="card shadow-sm">
                <div class="card-body">
                    <h4 class="card-title fw-bold mb-3"><i class="bi bi-folder2-open me-2 text-warning"></i>Explorateur : <span class="text-muted font-monospace fs-6">{displaypath}</span></h4>"""

        if self.path != "/":
            parent_path = os.path.dirname(os.path.dirname(self.path)) + "/"
            html_content += f'<p><a href="{parent_path}" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left me-1"></i>Dossier parent</a></p>'

        html_content += """
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead class="table-dark">
                                <tr>
                                    <th>Nom</th>
                                    <th>Type</th>
                                    <th>Propriétaire</th>
                                    <th class="text-end">Actions</th>
                                </tr>
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
                owner = name if name in USERS_DB else "Système"

            if is_dir:
                link = urllib.parse.quote(name) + "/"
                type_str = "Dossier personnel" if name in USERS_DB else "Dossier"
            else:
                link = urllib.parse.quote(name)
                type_str = "Fichier"

            html_content += f"""
                                <tr>
                                    <td><i class="bi {icon} me-2 fs-5"></i><a href="{link}" class="text-decoration-none fw-semibold text-dark">{display_name}</a></td>
                                    <td><span class="badge bg-light text-dark border">{type_str}</span></td>
                                    <td><span class="small text-muted">{owner}</span></td>
                                    <td class="text-end">"""

            if not is_dir:
                html_content += f'<a href="/generate-link?file={urllib.parse.quote(rel_path)}" class="btn btn-outline-info btn-sm me-1" title="Créer un lien de partage temporaire"><i class="bi bi-share"></i></a>'
                html_content += f'<a href="{link}" download class="btn btn-outline-success btn-sm me-1" title="Télécharger"><i class="bi bi-download"></i></a>'

            can_delete = False
            if user_role == "admin":
                can_delete = True
            elif owner == logged_in_user:
                can_delete = True

            if can_delete and name.lower() not in ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "lancement.bat"]:
                html_content += f'<a href="/delete?file={urllib.parse.quote(rel_path)}" class="btn btn-outline-danger btn-sm" onclick="return confirm(\'Êtes-vous sûr de vouloir supprimer cet élément ?\');" title="Supprimer"><i class="bi bi-trash"></i></a>'

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
        </body>
        </html>"""

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
    log_event(f"[*] Serveur sécurisé lancé sur le port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_event("[*] Arrêt du serveur.")
        httpd.server_close()
