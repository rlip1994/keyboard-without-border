"""
Keyboard Without Border (teclado_red.py) — Usa el teclado de la portátil en la PC grande por la red.

  En la PC grande (como administrador):   python teclado_red.py receptor
  En la portátil:                         python teclado_red.py emisor

Solo Windows. Solo usa la librería estándar de Python (no hay que instalar nada).

Cómo funciona:
  - La portátil capta cada tecla con un "hook" de Windows y la manda al instante por UDP.
  - Se manda el código físico de la tecla (scancode), que es lo que leen los juegos.
  - Cada 100 ms la portátil manda además la lista de teclas que tiene presionadas, así
    si un paquete se pierde en el Wi-Fi, la PC se corrige sola en menos de 0,1 s.
  - Si la PC deja de recibir datos por 0,5 s, suelta todas las teclas (nada de quedarse
    caminando sin parar).
  - Las dos compus se encuentran solas en la red: no hay que configurar IPs.
  - Los paquetes van cifrados y firmados con la CLAVE, así nadie más en la red puede
    leer lo que escribís ni mandar teclas falsas.

Ctrl + Alt + K en la portátil: pausa/reanuda el envío (para escribir en la portátil misma).
"""

import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac
import os
import socket
import struct
import sys
import threading
import time

def cargar_env(ruta=None):
    """Lee el archivo .env (junto a este script) y lo vuelca en os.environ.

    Formato: CLAVE=valor, una por línea. Se ignoran líneas vacías y las que
    empiezan con #. Las variables que ya existen en el entorno tienen prioridad.
    """
    ruta = ruta or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(ruta, encoding="utf-8-sig") as f:
            for linea in f:
                linea = linea.strip()
                if not linea or linea.startswith("#") or "=" not in linea:
                    continue
                nombre, valor = linea.split("=", 1)
                nombre, valor = nombre.strip(), valor.strip()
                if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "\"'":
                    valor = valor[1:-1]
                os.environ.setdefault(nombre, valor)
    except FileNotFoundError:
        pass


cargar_env()

# ======================= CONFIGURACIÓN (igual en las dos compus) =======================
# Los datos sensibles se leen del archivo .env (ver .env.example).
CLAVE = os.environ.get("TECLADO_CLAVE", "")           # contraseña compartida (obligatoria)
PUERTO = int(os.environ.get("TECLADO_PUERTO", "50505"))  # puerto UDP
IP_PC_MANUAL = os.environ.get("TECLADO_IP_PC", "")    # opcional: ej. "192.168.1.50" si el autodescubrimiento falla

if not CLAVE or CLAVE == "cambia-esta-clave":
    sys.exit("ERROR: falta TECLADO_CLAVE. Copiá .env.example a .env y poné una clave propia "
             "(la misma en las dos compus).")

TECLA_PAUSA_VK = 0x4B         # K  ->  Ctrl + Alt + K pausa/reanuda
LATIDO_S = 0.1                # cada cuánto se manda la lista de teclas presionadas
TIMEOUT_S = 0.5               # sin datos por este tiempo -> la PC suelta todas las teclas
DESCONEXION_S = 2.0           # sin respuesta por este tiempo -> avisa "sin respuesta" (pero sigue enviando)
REBUSCAR_S = 15.0             # sin respuesta por este tiempo -> vuelve a buscar la PC (solo sin IP manual)
AVISO_PICO_MS = 100           # avisa si un ping pasa de esto
ENVIAR_DOBLE = True           # cada tecla se manda 2 veces por si el Wi-Fi pierde una
# =======================================================================================

# ---------------------------------- Protocolo ----------------------------------
MAGIA = b"TK"
CAB = struct.Struct("<2sBII")  # magia, tipo, sesión, secuencia
T_EVENTO, T_ESTADO, T_PING, T_PONG, T_BUSCAR, T_OFERTA = range(1, 7)
LLAVE = hashlib.sha256(("teclado-red:" + CLAVE).encode()).digest()


def _flujo(tipo, sesion, seq, n):
    """Flujo de cifrado único para cada paquete."""
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(LLAVE + struct.pack("<BIII", tipo, sesion, seq, i)).digest()
        i += 1
    return out[:n]


def empacar(tipo, sesion, seq, datos=b""):
    cab = CAB.pack(MAGIA, tipo, sesion, seq)
    cif = bytes(a ^ b for a, b in zip(datos, _flujo(tipo, sesion, seq, len(datos))))
    return cab + cif + hmac.new(LLAVE, cab + cif, hashlib.sha256).digest()[:8]


def desempacar(pkt):
    if len(pkt) < CAB.size + 8:
        return None
    cuerpo, mac = pkt[:-8], pkt[-8:]
    if not hmac.compare_digest(mac, hmac.new(LLAVE, cuerpo, hashlib.sha256).digest()[:8]):
        return None  # clave incorrecta o paquete ajeno
    magia, tipo, sesion, seq = CAB.unpack_from(cuerpo)
    if magia != MAGIA:
        return None
    cif = cuerpo[CAB.size:]
    datos = bytes(a ^ b for a, b in zip(cif, _flujo(tipo, sesion, seq, len(cif))))
    return tipo, sesion, seq, datos


EVENTO = struct.Struct("<HBB")  # scancode, extendida, presionada
TECLA = struct.Struct("<HB")    # scancode, extendida

# ---------------------------------- Windows ----------------------------------
ULONG_PTR = ctypes.c_size_t
LRESULT = ctypes.c_ssize_t


def preparar_windows():
    global user32, kernel32
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Prioridad alta para que nada retrase las teclas
    kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), 0x80)  # HIGH_PRIORITY_CLASS
    # Desactiva "Edición rápida" de la consola: si se hace clic en la ventana,
    # la consola se congela y podría trabar el teclado.
    h = kernel32.GetStdHandle(-10)
    modo = wt.DWORD()
    if kernel32.GetConsoleMode(h, ctypes.byref(modo)):
        kernel32.SetConsoleMode(h, (modo.value & ~0x40) | 0x80)


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def mis_ips():
    """IPs de esta compu (sin la 127.x)."""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            if not info[4][0].startswith("127."):
                ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ips)


def destinos_busqueda():
    """A dónde mandar la búsqueda: IP manual, o el broadcast de cada red de esta compu."""
    if IP_PC_MANUAL:
        return [IP_PC_MANUAL]
    destinos = {"255.255.255.255"}
    for ip in mis_ips():
        destinos.add(ip.rsplit(".", 1)[0] + ".255")
    return sorted(destinos)


# ================================== RECEPTOR (PC grande) ==================================
class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ULONG_PTR)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD),
                ("dwFlags", wt.DWORD), ("time", wt.DWORD), ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]


class _UNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("u", _UNION)]


KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE = 0x1, 0x2, 0x8


SC_SHIFT_DER, VK_SHIFT_DER = 0x36, 0xA1


def inyectar(sc, ext, presionada):
    flags, vk = KEYEVENTF_SCANCODE, 0
    if sc == SC_SHIFT_DER:
        # El hook de Windows marca el Shift derecho como "extendido", pero E0 36 es un
        # "Shift falso" que Windows ignora. Se manda sin extendida y con el código virtual.
        flags, vk, ext = 0, VK_SHIFT_DER, 0
    if ext:
        flags |= KEYEVENTF_EXTENDEDKEY
    if not presionada:
        flags |= KEYEVENTF_KEYUP
    inp = INPUT(type=1, u=_UNION(ki=KEYBDINPUT(vk, sc, flags, 0, 0)))
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def receptor():
    preparar_windows()
    if not ctypes.windll.shell32.IsUserAnAdmin():
        log("AVISO: no estás como administrador. Juegos y programas abiertos como admin")
        log("       (League, el cliente de Riot, etc.) NO van a recibir las teclas.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", PUERTO))
    sock.settimeout(0.05)

    mi_sesion = int.from_bytes(os.urandom(4), "little")
    mi_seq = 0
    presionadas = set()
    sesion_actual, ultimo_seq, ultimo_rx = None, -1, time.monotonic()
    log(f"Receptor listo en el puerto {PUERTO}. Mis IPs: {', '.join(mis_ips()) or '?'}")
    log("Esperando a la portátil...")
    ultimo_aviso_clave = 0.0

    def responder(tipo, datos, destino):
        nonlocal mi_seq
        mi_seq += 1
        sock.sendto(empacar(tipo, mi_sesion, mi_seq, datos), destino)

    def soltar_todo(motivo):
        if presionadas:
            for sc, ext in list(presionadas):
                inyectar(sc, ext, False)
            presionadas.clear()
            log(f"Teclas soltadas ({motivo}).")

    while True:
        if time.monotonic() - ultimo_rx > TIMEOUT_S:
            soltar_todo("sin señal de la portátil")
        try:
            pkt, dir_ = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except ConnectionResetError:
            continue
        p = desempacar(pkt)
        if p is None:
            if pkt.startswith(MAGIA) and time.monotonic() - ultimo_aviso_clave > 5:
                ultimo_aviso_clave = time.monotonic()
                log(f"Llegó un paquete de {dir_[0]} pero la CLAVE no coincide.")
            continue
        tipo, ses, seq, datos = p

        if tipo == T_BUSCAR:
            responder(T_OFERTA, datos, dir_)
            log(f"Portátil encontrada en {dir_[0]}")
            continue

        if ses != sesion_actual:  # la portátil se reinició o se reconectó
            soltar_todo("nueva conexión")
            sesion_actual, ultimo_seq = ses, -1
            log(f"Conectado con {dir_[0]}")
        if seq <= ultimo_seq:
            continue  # duplicado o atrasado
        ultimo_seq, ultimo_rx = seq, time.monotonic()

        if tipo == T_EVENTO:
            sc, ext, down = EVENTO.unpack(datos)
            inyectar(sc, ext, bool(down))
            (presionadas.add if down else presionadas.discard)((sc, ext))
        elif tipo == T_ESTADO:
            n = datos[0]
            deseadas = {TECLA.unpack_from(datos, 1 + i * TECLA.size) for i in range(n)}
            for sc, ext in presionadas - deseadas:
                inyectar(sc, ext, False)
            for sc, ext in deseadas - presionadas:
                inyectar(sc, ext, True)
            presionadas = deseadas
        elif tipo == T_PING:
            responder(T_PONG, datos, dir_)


# ================================== EMISOR (portátil) ==================================
class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wt.DWORD), ("scanCode", wt.DWORD), ("flags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ULONG_PTR)]


HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wt.WPARAM, wt.LPARAM)
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x100, 0x101, 0x104, 0x105
LLKHF_EXTENDED, LLKHF_INJECTED = 0x01, 0x10
VK_CTRL = {0x11, 0xA2, 0xA3}
VK_ALT = {0x12, 0xA4, 0xA5}


class Emisor:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("", 0))
        self.sock.settimeout(0.2)
        self.lock = threading.Lock()
        self.sesion = int.from_bytes(os.urandom(4), "little")
        self.seq = 0
        self.pc = None
        self.activo = True
        self.presionadas = set()
        self.mods = set()
        self.pendientes = []  # mensajes para imprimir fuera del hook

    def _enviar(self, tipo, datos, destino, veces=1):  # llamar con self.lock tomado
        self.seq += 1
        pkt = empacar(tipo, self.sesion, self.seq, datos)
        for _ in range(veces):
            try:
                self.sock.sendto(pkt, destino)
            except OSError:
                pass

    def _datos_estado(self):
        teclas = list(self.presionadas)[:60]
        return bytes([len(teclas)]) + b"".join(TECLA.pack(sc, ext) for sc, ext in teclas)

    def procesar(self, vk, sc, ext, down):
        """Devuelve True si la tecla se manda a la PC (y se bloquea en la portátil)."""
        with self.lock:
            if vk in VK_CTRL or vk in VK_ALT:
                (self.mods.add if down else self.mods.discard)(vk)
            ctrl = bool(self.mods & VK_CTRL)
            alt = bool(self.mods & VK_ALT)

            if down and vk == TECLA_PAUSA_VK and ctrl and alt:
                self.activo = not self.activo
                if not self.activo and self.pc:
                    self.presionadas.clear()
                    self._enviar(T_ESTADO, self._datos_estado(), self.pc, 2)
                self.pendientes.append("ENVÍO REANUDADO" if self.activo
                                       else "EN PAUSA (escribiendo en la portátil)")
                return True

            if not self.activo or self.pc is None or sc == 0:
                return False

            if vk == VK_SHIFT_DER:
                ext = 0  # el hook lo reporta como extendido, pero no lo es
            tecla = (sc, int(ext))
            (self.presionadas.add if down else self.presionadas.discard)(tecla)
            self._enviar(T_EVENTO, EVENTO.pack(sc, int(ext), int(down)), self.pc,
                         2 if ENVIAR_DOBLE else 1)
            return True

    def hilo_red(self):
        nonce, ultimo_buscar, ultimo_ping, ultimo_pong = b"", 0.0, 0.0, 0.0
        latencias = []
        perdida = False
        while True:
            ahora = time.monotonic()
            while self.pendientes:
                log(self.pendientes.pop(0))

            if self.pc is None and ahora - ultimo_buscar > 1.0:
                nonce, ultimo_buscar = os.urandom(16), ahora
                with self.lock:
                    for ip in destinos_busqueda():
                        self._enviar(T_BUSCAR, nonce, (ip, PUERTO))

            if self.pc is not None:
                if ahora - ultimo_ping > 0.5:
                    ultimo_ping = ahora
                    with self.lock:
                        self._enviar(T_PING, struct.pack("<d", time.perf_counter()), self.pc)
                sin_resp = ahora - ultimo_pong
                if sin_resp > DESCONEXION_S and not perdida:
                    perdida = True
                    log(f"Sin respuesta de la PC hace {sin_resp:.1f} s (sigo enviando)...")
                if sin_resp > REBUSCAR_S and not IP_PC_MANUAL:
                    with self.lock:
                        self.pc = None
                        self.presionadas.clear()
                    perdida = False
                    log("La PC no responde. Buscándola de nuevo...")
                    continue

            try:
                pkt, dir_ = self.sock.recvfrom(2048)
            except (socket.timeout, ConnectionResetError):
                continue
            p = desempacar(pkt)
            if p is None:
                continue
            tipo, _, _, datos = p
            if tipo == T_OFERTA and self.pc is None and datos == nonce:
                with self.lock:
                    self.pc = (dir_[0], PUERTO)
                ultimo_pong = time.monotonic()
                log(f"Conectado a la PC en {dir_[0]}. ¡Listo para jugar!")
            elif tipo == T_PONG and len(datos) == 8:
                if perdida:
                    log(f"Señal recuperada después de {time.monotonic() - ultimo_pong:.1f} s.")
                    perdida = False
                ultimo_pong = time.monotonic()
                rtt = (time.perf_counter() - struct.unpack("<d", datos)[0]) * 1000
                if rtt > AVISO_PICO_MS:
                    log(f"Pico de ping: {rtt:.0f} ms")
                latencias.append(rtt)
                if len(latencias) >= 20:
                    log(f"Ping: promedio {sum(latencias)/len(latencias):.1f} ms, "
                        f"máximo {max(latencias):.1f} ms")
                    latencias.clear()

    def hilo_latido(self):
        while True:
            time.sleep(LATIDO_S)
            with self.lock:
                if self.pc is not None and self.activo:
                    self._enviar(T_ESTADO, self._datos_estado(), self.pc)


def emisor():
    preparar_windows()
    # Evita que la portátil se suspenda mientras el programa corre
    kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)

    e = Emisor()
    threading.Thread(target=e.hilo_red, daemon=True).start()
    threading.Thread(target=e.hilo_latido, daemon=True).start()

    user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wt.HINSTANCE, wt.DWORD]
    user32.SetWindowsHookExW.restype = wt.HHOOK
    user32.CallNextHookEx.argtypes = [wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM]
    user32.CallNextHookEx.restype = LRESULT
    kernel32.GetModuleHandleW.restype = wt.HMODULE

    @HOOKPROC
    def gancho(nCode, wParam, lParam):
        if nCode == 0:
            k = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            if not (k.flags & LLKHF_INJECTED):
                down = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
                if e.procesar(k.vkCode, k.scanCode, k.flags & LLKHF_EXTENDED, down):
                    return 1  # la tecla no se escribe en la portátil
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    hook = user32.SetWindowsHookExW(13, gancho, kernel32.GetModuleHandleW(None), 0)
    if not hook:
        log(f"No se pudo instalar el hook del teclado (error {ctypes.get_last_error()}).")
        return
    log(f"Emisor listo. Mis IPs: {', '.join(mis_ips()) or '?'}")
    log(f"Buscando la PC grande en: {', '.join(destinos_busqueda())}")
    log("Ctrl + Alt + K = pausar/reanudar. Para salir: pausá y cerrá esta ventana.")

    msg = wt.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


if __name__ == "__main__":
    modo = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    if modo == "receptor":
        receptor()
    elif modo == "emisor":
        emisor()
    else:
        print("Uso:\n  PC grande:  python teclado_red.py receptor\n"
              "  Portátil:   python teclado_red.py emisor")
