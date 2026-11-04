# Teclado por red (Mouse without b)

Usa el teclado de una **portátil** para controlar una **PC grande** a través de la red local. Pensado para jugar (envía scancodes físicos, que es lo que leen los juegos), con baja latencia y recuperación automática ante pérdida de paquetes en Wi-Fi.

- Solo **Windows**.
- Solo usa la **librería estándar de Python** (no hay nada que instalar).

## Archivos

| Archivo | Descripción |
|---|---|
| `teclado_red.py` | Programa completo (receptor y emisor). |
| `iniciar_receptor.bat` | Lanza el receptor minimizado en la PC grande. |
| `.env.example` | Plantilla de configuración. |
| `.env` | Tu configuración real y secreta (no se sube a git). |

## Configuración (`.env`)

1. Copiá `.env.example` a `.env`.
2. Completá los valores. **El `.env` debe tener la misma `TECLADO_CLAVE` en las dos computadoras.**

| Variable | Obligatoria | Por defecto | Descripción |
|---|---|---|---|
| `TECLADO_CLAVE` | Sí | — | Contraseña compartida para cifrar y firmar los paquetes. |
| `TECLADO_PUERTO` | No | `50505` | Puerto UDP. |
| `TECLADO_IP_PC` | No | vacío | IP de la PC grande, si el autodescubrimiento falla. |

Las variables de entorno del sistema tienen prioridad sobre el `.env`. Si falta `TECLADO_CLAVE` (o queda con el valor de ejemplo), el programa se detiene con un error claro.

## Uso

**En la PC grande** (como administrador, para que funcione con juegos o programas abiertos como admin):

```
python teclado_red.py receptor
```

o doble clic en `iniciar_receptor.bat`.

**En la portátil:**

```
python teclado_red.py emisor
```

Las dos se encuentran solas en la red (broadcast UDP); no hace falta configurar IPs salvo que falle el autodescubrimiento.

**Ctrl + Alt + K** en la portátil pausa/reanuda el envío (para escribir en la propia portátil).

## Cómo funciona

- **Hook de teclado:** la portátil capta cada tecla con un hook global de Windows (`WH_KEYBOARD_LL`), la bloquea localmente y la envía por UDP.
- **Receptor:** inyecta las teclas con `SendInput` usando scancodes.
- **Fiabilidad:** cada evento se manda 2 veces, y cada 100 ms se envía la lista completa de teclas presionadas; si se pierde un paquete, la PC se corrige sola. Si pasan 0,5 s sin datos, el receptor suelta todas las teclas.
- **Descubrimiento:** el emisor manda un paquete de búsqueda a la IP manual o al broadcast de cada red local; el receptor responde con una oferta.
- **Seguridad:** los paquetes se cifran (flujo derivado de SHA-256 con la clave) y se firman con HMAC-SHA256 (8 bytes), con número de secuencia para descartar duplicados. Quien no tenga la clave no puede leer ni inyectar teclas. Es un esquema casero pensado para una LAN doméstica, no un sustituto de TLS/VPN.
- **Monitoreo:** el emisor mide el ping cada 0,5 s, avisa de picos (>100 ms) y de pérdida de señal, y vuelve a buscar la PC si no responde en 15 s.

## Parámetros avanzados

En `teclado_red.py` (sección de configuración): `LATIDO_S`, `TIMEOUT_S`, `DESCONEXION_S`, `REBUSCAR_S`, `AVISO_PICO_MS`, `ENVIAR_DOBLE` y `TECLA_PAUSA_VK`.

## Solución de problemas

- **"la CLAVE no coincide"** en el receptor: los `.env` de las dos compus tienen distinta `TECLADO_CLAVE`.
- **No se encuentran:** permití Python en el firewall de Windows (UDP, puerto configurado) o definí `TECLADO_IP_PC` en la portátil.
- **Las teclas no llegan a un juego:** ejecutá el receptor como administrador.
