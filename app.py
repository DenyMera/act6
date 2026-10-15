"""
Practica SAST/DAST - Codigo seguro para los 6 casos (+ MFA).
Instalar: pip install flask bcrypt pyotp
"""
import sqlite3, logging, os, time, html
import bcrypt, pyotp
from flask import Flask, request, redirect, render_template_string

# ======================================================================
# CASO 1 - Inyeccion SQL: consultas parametrizadas (SQLite)
# ======================================================================
def login_seguro(username, password_hash_check):
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
# CASO 2 - Fuga de informacion: try/except + log interno123
# ======================================================================
logging.basicConfig(filename="app.log", level=logging.ERROR)

def leer_edad(valor):
    try:
        edad = int(valor)
        if not 0 < edad < 120:
            raise ValueError("fuera de rango")
        return {"ok": True, "edad": edad}
    except ValueError:
        logging.error("Edad invalida recibida", exc_info=True)   # detalle SOLO en el log
        return {"ok": False, "mensaje": "Dato invalido. Ingrese un numero."}  # mensaje generico

# ======================================================================
# CASO 3 - Contrasenas seguras con bcrypt (y secretos en variables de entorno)
# ======================================================================
DB_PASSWORD = os.environ.get("DB_PASSWORD")      # NUNCA escrita en el .py

def hashear(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verificar(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# ======================================================================
# CASO 4 - XSS: escape automatico de Jinja2 + CSP
# ======================================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cambiar-en-produccion")
quejas = []

@app.route("/queja", methods=["GET", "POST"])
def queja():
    if request.method == "POST":
        quejas.append(request.form.get("comentario", "")[:500])
        return redirect("/queja")
    # {{ q }} se escapa automaticamente; NO usar |safe
    return render_template_string(
        "<h1>Quejas</h1>{% for q in quejas %}<p>{{ q }}</p>{% endfor %}", quejas=quejas)

@app.after_request
def cabeceras(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
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
intentos = {}   # usuario -> (fallos, ultimo_fallo)

def login_con_limite(usuario, password, hash_correcto):
    fallos, ultimo = intentos.get(usuario, (0, 0))
    if fallos >= MAX_INTENTOS and time.time() - ultimo < BLOQUEO_SEG:
        return "Cuenta bloqueada temporalmente. Intente mas tarde."
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
# PRUEBAS (python casos_1_a_6.py)
# ======================================================================
if __name__ == "__main__":
    os.environ["ALLOW_HTTP"] = "1"
    print("C1 payload SQLi ->", login_seguro("jayesh'; delete from user where id='1", None))
    print("C1 usuario valido ->", login_seguro("jayesh", None))
    print("C2 'abc' ->", leer_edad("abc"), "| '25' ->", leer_edad("25"))
    h = hashear("Clave#2026"); print("C3 bcrypt ok/mal ->", verificar("Clave#2026", h), verificar("otra", h))
    c = app.test_client()
    c.post("/queja", data={"comentario": "<script>alert(1)</script>"})
    r = c.get("/queja").get_data(as_text=True); print("C4 ->", r)
    print("C4 CSP ->", "Content-Security-Policy" in c.get("/queja").headers)
    del os.environ["ALLOW_HTTP"]
    rr = c.get("/queja", base_url="http://localhost"); print("C5 ->", rr.status_code, rr.headers["Location"])
    print("C6 ->", [login_con_limite("ana", "mala", h)[:20] for _ in range(7)])
    s, uri = configurar_mfa(); print("MFA ->", verificar_mfa(s, pyotp.TOTP(s).now()), verificar_mfa(s, "000000"))