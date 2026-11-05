import http.server
import os
import io
import urllib.parse
import html
import shutil
import uuid
from http import cookies

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
                        
            print(f"[*] Fichier '{filename}' lu avec succès ! Comptes chargés : {list(users_db.keys())}")
        except Exception as e:
            print(f"[!] Erreur lors de la lecture du fichier : {e}")
    else:
        print(f"[!] Fichier '{filename}' introuvable. Compte de secours 'admin':'admin'")
        users_db["admin"] = {"password": "admin", "role": "admin"}
        
    return users_db

USERS_DB = load_users()
SESSIONS = {}  # Stockage temporaire des sessions connectées

UPLOAD_DIR = os.path.join(os.getcwd(), "Echange de fichiers")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def check_auth(self):
        # Vérifie si l'utilisateur possède un cookie de session valide
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
        
        # Route de la page de connexion
        if parsed_url.path == "/login":
            self.send_login_page()
            return

        # Route de déconnexion
        if parsed_url.path == "/logout":
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

        # Vérification de la session active
        logged_in_user = self.check_auth()
        if not logged_in_user:
            self.send_response(303)
            self.send_header('Location', '/login')
            self.end_headers()
            return

        # Gestion de la suppression par l'Admin
        if parsed_url.path == "/delete":
            user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")
            if user_role != "admin":
                self.send_response(403)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><head><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'></head><body class='bg-light text-center py-5'>")
                self.wfile.write(b"<h2 class='text-danger'>Acces Interdit (403)</h2>")
                self.wfile.write(b"<p>Action reservee exclusivement aux administrateurs.</p>")
                self.wfile.write(b"<a href='/' class='btn btn-secondary'>Retour a l'accueil</a></body></html>")
                return

            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "file" in query_params:
                filename_to_delete = query_params["file"][0]
                filename_to_delete = os.path.basename(filename_to_delete)
                
                target_path = os.path.join(os.getcwd(), filename_to_delete)
                if not os.path.exists(target_path):
                    target_path = os.path.join(UPLOAD_DIR, filename_to_delete)

                protected_files = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "lancement.bat"]
                if os.path.exists(target_path) and filename_to_delete.lower() not in protected_files:
                    try:
                        if os.path.isdir(target_path):
                            shutil.rmtree(target_path)
                        else:
                            os.remove(target_path)
                        print(f"[-] Fichier supprime par l'admin '{logged_in_user}' : {filename_to_delete}")
                    except Exception as e:
                        print(f"[!] Erreur lors de la suppression : {e}")

            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        # Contrôle d'accès RBAC
        path_decoded = urllib.parse.unquote(self.path).lstrip('/')
        fichiers_sensibles = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "lancement.bat"]
        est_sensible = path_decoded.lower() in fichiers_sensibles
        est_dossier_admin = path_decoded.lower().startswith("admin")
        
        if est_sensible or est_dossier_admin:
            user_role = USERS_DB.get(logged_in_user, {}).get("role", "user")
            if user_role != "admin":
                self.send_response(403)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><head><link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'></head><body class='bg-light text-center py-5'>")
                self.wfile.write(b"<div class='card shadow-sm d-inline-block p-4' style='max-width: 450px;'>")
                self.wfile.write(b"<h2 class='text-danger mb-3'>Acces Interdit (403)</h2>")
                self.wfile.write(b"<p class='text-muted'>Cette zone est reservee exclusivement aux comptes avec le role <b>admin</b>.</p>")
                self.wfile.write(b"<a href='/' class='btn btn-outline-primary'>Retour a l'accueil</a></div></body></html>")
                return

        super().do_GET()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        # Traitement du formulaire de connexion
        if parsed_url.path == "/login":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(body)
            
            username = params.get("username", [""])[0].strip()
            password = params.get("password", [""])[0].strip()

            if username in USERS_DB and USERS_DB[username]["password"] == password:
                session_id = str(uuid.uuid4())
                SESSIONS[session_id] = username

                self.send_response(303)
                self.send_header('Set-Cookie', f'session_id={session_id}; Path=/')
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.send_login_page(error="Identifiant ou mot de passe incorrect.")
            return

        # Traitement des uploads de fichiers
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
            self.wfile.write(b"Requete invalide.")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            boundary = content_type.split("boundary=")[1].encode('utf-8')
            parts = body.split(boundary)
            for part in parts:
                if b'filename="' in part:
                    header_part, file_data = part.split(b'\r\n\r\n', 1)
                    file_data = file_data.rstrip(b'\r\n--')
                    
                    filename_start = header_part.find(b'filename="') + 10
                    filename_end = header_part.find(b'"', filename_start)
                    filename = header_part[filename_start:filename_end].decode('utf-8')
                    
                    if filename:
                        filename = os.path.basename(filename)
                        filepath = os.path.join(UPLOAD_DIR, filename)
                        
                        with open(filepath, "wb") as f:
                            f.write(file_data)
                        print(f"[+] Fichier uploade avec succes dans 'Echange de fichiers' : {filename} par {logged_in_user}")
        except Exception as e:
            print(f"[!] Erreur lors de l'upload : {e}")

        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

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
                    <p class="text-light small">Veuillez vous identifier pour acceder au cloud</p>
                </div>
                {f'<div class="alert alert-danger py-2 small text-center"><i class="bi bi-exclamation-triangle-fill me-1"></i>{error}</div>' if error else ''}
                <form action="/login" method="POST">
                    <div class="mb-3">
                        <label class="form-label fw-semibold"><i class="bi bi-person-fill me-1"></i> Nom d'utilisateur</label>
                        <input type="text" name="username" class="form-control" required autofocus autocomplete="username">
                    </div>
                    <div class="mb-3">
                        <label class="form-label fw-semibold"><i class="bi bi-key-fill me-1"></i> Mot de passe</label>
                        <input type="password" name="password" class="form-control" required autocomplete="current-password">
                    </div>
                    <button type="submit" class="btn btn-warning w-100 fw-bold py-2 shadow-sm mt-2">
                        <i class="bi bi-box-arrow-in-right me-1"></i> Se connecter
                    </button>
                </form>
            </div>
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

        list_dir.sort(key=lambda a: (not os.path.isdir(os.path.join(path, a)), a.lower()))
        f = io.BytesIO()
        displaypath = html.escape(urllib.parse.unquote(self.path))
        
        # En-tête HTML avec Bootstrap 5 + Bootstrap Icons
        f.write(b'<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">')
        f.write(b'<meta name="viewport" content="width=device-width, initial-scale=1">')
        f.write(f'<title>Echange de Fichiers - {displaypath}</title>'.encode('utf-8'))
        f.write(b'<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">')
        f.write(b'<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">')
        f.write(b'</head><body class="bg-light">')
        
        # Navbar élégante
        f.write(b'<nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm mb-4"><div class="container">')
        f.write(b'<a class="navbar-brand font-monospace fw-bold" href="/"><i class="bi bi-cloud-arrow-down-fill text-primary me-2"></i>Echange Cloud</a>')
        f.write(b'<div class="d-flex align-items-center gap-3">')
        
        role_badge = '<span class="badge bg-danger">Admin</span>' if user_role == "admin" else '<span class="badge bg-info text-dark">User</span>'
        f.write(f'<span class="text-light me-2"><i class="bi bi-person-circle me-1"></i>{logged_in_user} {role_badge}</span>'.encode('utf-8'))
        f.write(b'<a href="/logout" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right me-1"></i>Deconnexion</a>')
        f.write(b'</div></div></nav>')
        
        f.write(b'<div class="container">')
        
        # Carte d'Upload de fichiers
        f.write(b'<div class="card shadow-sm mb-4"><div class="card-body">')
        f.write(b'<h5 class="card-title mb-3"><i class="bi bi-upload text-success me-2"></i>Televerser un nouveau fichier</h5>')
        f.write(b'<form action="/" method="POST" enctype="multipart/form-data" class="row g-2 align-items-center">')
        f.write(b'<div class="col-auto flex-grow-1"><input class="form-control" type="file" name="file" required></div>')
        f.write(b'<div class="col-auto"><button type="submit" class="btn btn-success fw-bold"><i class="bi bi-cloud-upload me-1"></i>Uploader</button></div>')
        f.write(b'</form></div></div>')
        
        # Liste des fichiers sous forme de carte moderne
        f.write(b'<div class="card shadow-sm"><div class="card-header bg-white py-3 d-flex justify-content-between align-items-center">')
        f.write(f'<h5 class="mb-0 text-secondary"><i class="bi bi-folder2-open me-2"></i>Contenu : <span class="text-dark fw-bold">{displaypath}</span></h5>'.encode('utf-8'))
        f.write(b'</div><ul class="list-group list-group-flush">')
        
        fichiers_a_masquer = ["mot de passe.txt", "server_secure.py", "server_secure_2.py", "lancement.bat"]

        for name in list_dir:
            if user_role != "admin" and name.lower() in fichiers_a_masquer:
                continue

            fullname = os.path.join(path, name)
            is_dir = os.path.isdir(fullname)
            displayname = name + "/" if is_dir else name
            linkname = name + "/" if is_dir else name
            
            icon_class = self.get_file_icon(name, is_dir)
            
            f.write(b'<li class="list-group-item d-flex justify-content-between align-items-center py-3">')
            f.write(b'<div class="d-flex align-items-center">')
            f.write(f'<i class="bi {icon_class} fs-4 me-3"></i>'.encode('utf-8'))
            f.write(f'<a href="{urllib.parse.quote(linkname)}" class="text-decoration-none text-dark fw-semibold">{html.escape(displayname)}</a>'.encode('utf-8'))
            f.write(b'</div>')
            
            f.write(b'<div class="btn-group">')
            f.write(f'<a href="{urllib.parse.quote(linkname)}" class="btn btn-sm btn-outline-primary"><i class="bi bi-download me-1"></i>Ouvrir</a>'.encode('utf-8'))
            
            if user_role == "admin" and name.lower() not in fichiers_a_masquer:
                f.write(f'<a href="/delete?file={urllib.parse.quote(name)}" class="btn btn-sm btn-outline-danger" onclick="return confirm(\'Voulez-vous vraiment supprimer {html.escape(name)} ?\');"><i class="bi bi-trash-fill"></i></a>'.encode('utf-8'))
            
            f.write(b'</div></li>')
        
        f.write(b'</ul></div></div></body></html>')
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    server_address = ("0.0.0.0", port)
    httpd = http.server.ThreadingHTTPServer(server_address, SecureHandler)
    print(f"[*] Serveur lancé et à l'écoute sur le port {port}")
    httpd.serve_forever()
