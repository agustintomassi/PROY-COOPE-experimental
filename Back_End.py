import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, jsonify, redirect, render_template, request,
                   session, url_for)

app = Flask(__name__)

# La base se busca junto a este archivo, sin importar desde qué carpeta
# se ejecute el programa (así nunca crea una cooperadora.db vacía por error).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUTA_DB = os.path.join(BASE_DIR, 'cooperadora.db')

MONTO_FIJO = 4000.0   # Monto actual de la cooperadora

# ---------------------------------------------------------------------------
# ACCESO CON PIN
# ---------------------------------------------------------------------------
# Para cambiar el PIN: reemplazá '5555' por el nuevo (4 números, entre comillas).
PIN_ACCESO = os.environ.get('COOPERADORA_PIN', '5555')

INTENTOS_MAXIMOS = 5          # fallos seguidos permitidos...
BLOQUEO_SEGUNDOS = 5 * 60     # ...y después se bloquea ese dispositivo 5 minutos
DURACION_SESION = timedelta(minutes=30) # sin actividad por este tiempo, vuelve a pedir el PIN

# Para firmar la "cookie de sesión" Flask necesita una clave secreta.
# Se genera una sola vez y se guarda en el archivo .secret_key (no lo compartas).
def cargar_clave_secreta():
    clave = os.environ.get('SECRET_KEY')
    if clave:
        return clave
    ruta = os.path.join(BASE_DIR, '.secret_key')
    if not os.path.exists(ruta):
        with open(ruta, 'w') as archivo:
            archivo.write(secrets.token_hex(32))
    with open(ruta) as archivo:
        return archivo.read().strip()

app.secret_key = cargar_clave_secreta()
app.config.update(
    TEMPLATES_AUTO_RELOAD=True,      # si editás un HTML, se nota sin reiniciar el servidor
    PERMANENT_SESSION_LIFETIME=DURACION_SESION,
    SESSION_COOKIE_HTTPONLY=True,    # el JavaScript de la página no puede leer la cookie
    SESSION_COOKIE_SAMESITE='Lax',   # otras webs no pueden mandar pedidos con tu sesión
)

_intentos = {}   # { ip: (fallos_seguidos, bloqueado_hasta) }  -> se borra al reiniciar

# Valores permitidos (tienen que coincidir con los <option> del formulario)
TIPOS_VALIDOS = {'Alumno', 'Docente', 'No docente'}
CARRERAS_VALIDAS = {
    'Analista de Sistemas', 'Desarrollo de Software',
    'Ciencia de Datos e IA', 'IoT', 'Seguridad e Higiene',
}
ANIOS_VALIDOS = {'1°', '2°', '3°'}


def conectar_db():
    print(f"--> Conectando a la base de datos en: {RUTA_DB}")
    return sqlite3.connect(RUTA_DB)


def error(mensaje, codigo=400):
    return jsonify(ok=False, error=mensaje), codigo


@app.after_request
def no_guardar_en_cache(respuesta):
    # Que el navegador no guarde copias del formulario ni del login:
    # así, tras cerrar sesión, "volver atrás" no muestra la pantalla anterior.
    if request.endpoint != 'static':
        respuesta.headers['Cache-Control'] = 'no-store'
    return respuesta


def ip_cliente():
    # Detrás de Cloudflare, la IP real de la persona viene en este encabezado
    return request.headers.get('CF-Connecting-IP', request.remote_addr)


def login_requerido(vista):
    """Decorador: si no ingresó el PIN, no deja pasar a la ruta."""
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if not session.get('autenticado'):
            if request.method == 'GET':
                return redirect(url_for('login'))
            # Pedido del formulario (fetch): se responde en JSON para que el JS redirija
            return error('Sesión vencida. Ingresá el PIN de nuevo.', 401)
        return vista(*args, **kwargs)
    return envoltura


def preparar_db():
    """Deja la base lista para las estadísticas. Se puede ejecutar siempre:
    si ya está todo en orden, no cambia nada.

    - contribuyente: guarda los datos ACTUALES de cada persona.
    - cuota: guarda además una "foto" del tipo, carrera y año que tenía la
      persona EN EL MOMENTO de pagar. Así el historial no cambia aunque
      después pase de año o de carrera."""
    if not os.path.exists(RUTA_DB):
        print(f"AVISO: no se encontró {RUTA_DB}; se crea una base nueva.")

    with closing(conectar_db()) as con:
        con.execute('''
            CREATE TABLE IF NOT EXISTS contribuyente (
                dni TEXT PRIMARY KEY,
                nombre TEXT NOT NULL,
                apellido TEXT NOT NULL,
                mail TEXT NOT NULL,
                tipo TEXT NOT NULL,
                carrera TEXT,
                anio TEXT
            )''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS cuota (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TEXT NOT NULL,
                monto REAL NOT NULL,
                contribuyente_id TEXT NOT NULL,
                tipo TEXT,
                carrera TEXT,
                anio TEXT,
                FOREIGN KEY (contribuyente_id) REFERENCES contribuyente(dni)
            )''')

        # Bases creadas antes de este cambio: agregar las columnas que falten
        existentes = {fila[1] for fila in con.execute('PRAGMA table_info(cuota)')}
        for columna in ('tipo', 'carrera', 'anio'):
            if columna not in existentes:
                con.execute(f'ALTER TABLE cuota ADD COLUMN {columna} TEXT')

        # Pagos viejos sin "foto": se completan con los datos actuales de la persona
        con.execute('''
            UPDATE cuota SET
                tipo    = (SELECT tipo    FROM contribuyente WHERE dni = cuota.contribuyente_id),
                carrera = (SELECT carrera FROM contribuyente WHERE dni = cuota.contribuyente_id),
                anio    = (SELECT anio    FROM contribuyente WHERE dni = cuota.contribuyente_id)
            WHERE tipo IS NULL
        ''')
        con.commit()


preparar_db()


# Pantalla de acceso
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('autenticado'):
        return redirect(url_for('index'))
    if request.method == 'GET':
        return render_template('login.html')

    ip = ip_cliente()
    ahora = time.time()
    fallos, bloqueado_hasta = _intentos.get(ip, (0, 0))

    if bloqueado_hasta > ahora:
        minutos = int((bloqueado_hasta - ahora) // 60) + 1
        return render_template(
            'login.html',
            error=f'Demasiados intentos. Probá de nuevo en {minutos} min.'), 429

    pin = (request.form.get('pin') or '').strip()
    # compare_digest compara sin dar pistas por el tiempo que tarda
    if hmac.compare_digest(pin.encode(), PIN_ACCESO.encode()):
        _intentos.pop(ip, None)
        session.clear()
        session.permanent = True
        session['autenticado'] = True
        return redirect(url_for('index'))

    fallos += 1
    if fallos >= INTENTOS_MAXIMOS:
        _intentos[ip] = (0, ahora + BLOQUEO_SEGUNDOS)
        print(f"PIN incorrecto {INTENTOS_MAXIMOS} veces desde {ip}: bloqueado.")
    else:
        _intentos[ip] = (fallos, 0)
        print(f"PIN incorrecto desde {ip} ({fallos}/{INTENTOS_MAXIMOS})")
    return render_template('login.html', error='PIN incorrecto.'), 401


@app.route('/salir')
def salir():
    session.clear()
    return redirect(url_for('login'))


# Ruta 1: muestra el formulario (solo con PIN)
@app.route('/')
@login_requerido
def index():
    return render_template('formularioFinal.html')


# Ruta 2: recibe los datos y los guarda
@app.route('/registrar', methods=['POST'])
@login_requerido
def registrar():
    nombre = (request.form.get('nombre') or '').strip()
    apellido = (request.form.get('apellido') or '').strip()
    dni = (request.form.get('dni') or '').strip()
    email = (request.form.get('email') or '').strip()
    tipo = (request.form.get('tipo') or '').strip()
    carrera = (request.form.get('carrera') or '').strip() or None   # None si no viene
    anio = (request.form.get('anio') or '').strip() or None

    # ---- Validación en el servidor (el navegador se puede saltear) ----
    if not (nombre and apellido and email):
        return error('Completá nombre, apellido y email.')
    if not re.fullmatch(r'\d{7,8}', dni):
        return error('El DNI debe tener 7 u 8 números.')
    if tipo not in TIPOS_VALIDOS:
        return error('Elegí un tipo de contribuyente válido.')

    if tipo == 'Alumno':
        if carrera not in CARRERAS_VALIDAS or anio not in ANIOS_VALIDOS:
            return error('Elegí la carrera y el año.')
    else:
        # Docentes y no docentes: nunca se guardan carrera ni año
        carrera = None
        anio = None

    fecha_actual = datetime.now().strftime('%Y-%m-%d')

    try:
        with closing(conectar_db()) as conexion:
            cursor = conexion.cursor()

            # 1. Alta: si el DNI no existe, se crea con todos sus datos
            cursor.execute('''
                INSERT OR IGNORE INTO contribuyente
                    (dni, nombre, apellido, mail, tipo, carrera, anio)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (dni, nombre, apellido, email, tipo, carrera, anio))

            # 2. Si ya existía, se actualiza SOLO tipo, carrera y año (lo que cambia
            #    con el tiempo). Nombre, apellido y mail no se pisan: así un DNI
            #    mal tipeado no puede pisar los datos de otra persona.
            cursor.execute('''
                UPDATE contribuyente SET tipo = ?, carrera = ?, anio = ?
                WHERE dni = ?
            ''', (tipo, carrera, anio, dni))

            # 3. Pago, con la "foto" del tipo/carrera/año de este momento
            cursor.execute('''
                INSERT INTO cuota
                    (fecha, monto, contribuyente_id, tipo, carrera, anio)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (fecha_actual, MONTO_FIJO, dni, tipo, carrera, anio))

            conexion.commit()

        print(f"¡Éxito! Pago guardado para: {nombre} {apellido} (DNI: {dni}, {tipo})")
        return jsonify(ok=True, mensaje='¡Registrado con éxito!')

    except Exception as e:
        print(f"Error al guardar en la base de datos: {e}")
        return error('Hubo un error al registrar. Intentá de nuevo.', 500)


if __name__ == '__main__':
    # IMPORTANTE: con debug=True, si hay un error Flask muestra una consola de
    # Python en el navegador. Si la app es accesible desde internet (Cloudflare),
    # eso es un riesgo enorme. Dejalo en False mientras uses el túnel.
    print("=" * 60)
    print(f"Servidor iniciado desde la carpeta: {BASE_DIR}")
    print(f"Plantillas leídas de:               {os.path.join(BASE_DIR, 'templates')}")
    print(f"La sesión vence tras {int(DURACION_SESION.total_seconds() // 60)} min sin actividad")
    print("=" * 60)
    app.run(debug=False)
