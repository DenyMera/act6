"""
Practica SAST/DAST - Codigo seguro para los 6 casos (+ MFA) - VERSION CORREGIDA
Instalar: pip install flask flask-wtf bcrypt pyotp

Uso:
  python app.py            -> ejecuta las pruebas de los 6 casos en consola
  python app.py servidor   -> levanta la app en http://127.0.0.1:5001/queja (para OWASP ZAP)

"""
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import bcrypt
import pyotp
from flask import Flask, redirect, render_template_string, request
from flask_wtf.csrf import CSRFProtect
from werkzeug.serving import WSGIRequestHandler

# ======================================================================
# CASO 1 - Inyeccion SQL: consultas parametrizadas (SQLite)
# ======================================================================
def login_seguro(username, _password_hash_check):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE user (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT INTO user (username, password) VALUES (?, ?)", ("jayesh", "x"))
    # INSEGURO: cur.execute("SELECT * FROM user WHERE username = '" + username + "'")
    cur.execute("SELECT id, username FROM user WHERE username = ?", (username,))  # SEGURO
    fila = cur.fetchone()
    conn.close()
    return fila

# ======================================================================
# CASO 2 - Fuga de informacion: try/except + log interno
# ======================================================================
logging.basicConfig(filename="app.log", level=logging.ERROR)

def leer_edad(valor):
    try:
        edad = int(valor)
        if not 0 < edad < 120:
            raise ValueError("fuera de rango")
        return {"ok": True, "edad": edad}
    except (TypeError, ValueError):
        logging.exception("Edad invalida recibida")
        return {"ok": False, "mensaje": "Dato invalido. Ingrese un numero."}

# ======================================================================
# CASO 3 - Contrasenas seguras con bcrypt (y secretos en variables de entorno)
# ======================================================================
def hashear(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verificar(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# ======================================================================
# CASO 4 - XSS: escape automatico de Jinja2 + CSP  (+ proteccion CSRF)
# ======================================================================
app = Flask(__name__)

_clave = os.environ.get("SECRET_KEY")
if not _clave:
    _clave = secrets.token_hex(32)
    logging.warning("SECRET_KEY no definida: se uso una clave temporal.")
app.config["SECRET_KEY"] = _clave

# [ZAP] Cookie de sesion con atributos de seguridad (SameSite, HttpOnly, Secure)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("ALLOW_HTTP") != "1"

csrf = CSRFProtect(app)

quejas = []
intentos = {}
intentos_lock = threading.Lock()


@app.route("/queja", methods=["GET", "POST"])
def queja():
    if request.method == "POST":
        comentario = request.form.get("comentario", "") or ""
        quejas.append(comentario[:500])
        return redirect("/queja")
    # {{ q }} se escapa automaticamente; NO usar |safe
    return render_template_string(
        """
        <h1>Quejas</h1>
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <textarea name="comentario" maxlength="500"></textarea>
            <button type="submit">Enviar</button>
        </form>
        {% for q in quejas %}<p>{{ q }}</p>{% endfor %}
        """,
        quejas=quejas,
    )

@app.after_request
def cabeceras(resp):
    # [ZAP] CSP completa: frame-ancestors, form-action y base-uri no heredan de default-src
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ======================================================================
# CASO 5 - Forzar HTTPS
# ======================================================================
@app.before_request
def forzar_https():
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    if proto != "https" and os.environ.get("ALLOW_HTTP") != "1":
        return redirect(request.url.replace("http://", "https://", 1), code=301)

# ======================================================================
# CASO 6 - Fuerza bruta: limite de intentos + bloqueo temporal
# ======================================================================
MAX_INTENTOS, BLOQUEO_SEG = 5, 300


def login_con_limite(usuario, password, hash_correcto):
    with intentos_lock:
        fallos, ultimo = intentos.get(usuario, (0, 0))
        if fallos >= MAX_INTENTOS:
            if time.time() - ultimo < BLOQUEO_SEG:
                return "Cuenta bloqueada temporalmente. Intente mas tarde."
            fallos = 0  # el bloqueo expiro: se reinicia el contador
        if verificar(password, hash_correcto):
            intentos.pop(usuario, None)
            return "Acceso concedido"
        intentos[usuario] = (fallos + 1, time.time())
        return "Credenciales invalidas"

# ======================================================================
# EXTRA - MFA (TOTP)
# ======================================================================
def configurar_mfa():
    secreto = pyotp.random_base32()
    uri = pyotp.TOTP(secreto).provisioning_uri(name="usuario@correo.com", issuer_name="MiApp")
    return secreto, uri          # mostrar la URI como QR en Google Authenticator

def verificar_mfa(secreto, codigo):
    return pyotp.TOTP(secreto).verify(codigo, valid_window=1)

# ======================================================================
# PRUEBAS Y SERVIDOR
# ======================================================================
class ZAPRequestHandler(WSGIRequestHandler):
    def version_string(self):
        return "webserver"


def _token(cliente):
    html = cliente.get("/queja").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


if __name__ == "__main__":
    os.environ["ALLOW_HTTP"] = "1"          # solo para pruebas locales por HTTP
    app.config["SESSION_COOKIE_SECURE"] = False

    if len(sys.argv) > 1 and sys.argv[1] == "servidor":
        # Objetivo del escaneo de OWASP ZAP: http://127.0.0.1:5001/queja
        app.run(host="127.0.0.1", port=5001, request_handler=ZAPRequestHandler)
        sys.exit(0)

    print("C1 payload SQLi ->", login_seguro("jayesh'; delete from user where id='1", None))
    print("C1 usuario valido ->", login_seguro("jayesh", None))
    print("C2 'abc' ->", leer_edad("abc"), "| '25' ->", leer_edad("25"))
    h = hashear("Clave#2026"); print("C3 bcrypt ok/mal ->", verificar("Clave#2026", h), verificar("otra", h))
    c = app.test_client()
    tk = _token(c)
    print("C4 POST sin token CSRF ->", c.post("/queja", data={"comentario": "x"}).status_code)  # 400
    c.post("/queja", data={"comentario": "<script>alert(1)</script>", "csrf_token": tk})
    r = c.get("/queja").get_data(as_text=True); print("C4 ->", r)
    resp = c.get("/queja")
    print("C4 CSP ->", resp.headers.get("Content-Security-Policy"))
    print("ZAP Server ->", resp.headers.get("Server"))
    del os.environ["ALLOW_HTTP"]
    rr = c.get("/queja", base_url="http://localhost")
    print("C5 ->", rr.status_code, rr.headers.get("Location"))
    print("C6 ->", [login_con_limite("ana", "mala", h)[:20] for _ in range(7)])
    s, uri = configurar_mfa(); print("MFA ->", verificar_mfa(s, pyotp.TOTP(s).now()), verificar_mfa(s, "000000"))
