#!/usr/bin/env python3
"""
php_version_recon.py
---------------------
Script de reconocimiento para identificar la version de PHP usada por una
lista de aplicaciones web, pensado UNICAMENTE para uso en pentests o
programas de bug bounty con autorizacion explicita sobre los activos.

Lee un fichero de texto con un activo (URL) por linea, lanza varias
tecnicas de fingerprinting contra cada uno y vuelca los resultados en un
Excel: una fila por activo, una columna por tecnica/herramienta.

Requisitos:
    pip install requests openpyxl

Herramientas externas opcionales (si estan instaladas en el PATH, se usan；
si no, esa columna se rellena con "N/A - herramienta no encontrada"):
    - nmap        (script http-php-version)
    - whatweb
    - nikto
    - nuclei
    - ffuf

Uso:
    python3 php_version_recon.py -i activos.txt -o resultados.xlsx
    python3 php_version_recon.py -i activos.txt -o resultados.xlsx --full
        (--full activa nikto y nuclei, mas lentos)

Formato del fichero de entrada (un activo por linea):
    https://ejemplo1.com
    https://ejemplo2.com
    http://192.168.1.10:8080
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.utils.exceptions import IllegalCharacterError
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.chart import PieChart, BarChart, Reference
from openpyxl.chart.label import DataLabelList

requests.packages.urllib3.disable_warnings()

TIMEOUT = 10
PHPINFO_PATHS = [
    "phpinfo.php", "info.php", "test.php", "i.php",
    "php_info.php", "_phpinfo.php", "pinfo.php",
]

# Ficheros de log de errores de PHP que a veces quedan expuestos en la raiz
# del document root cuando log_errors=On y error_log no se reubica fuera de
# el (ruta por defecto de muchas instalaciones PHP/Apache mal configuradas).
PHP_ERROR_LOG_PATHS = [
    "error_log", "php_errorlog", "error.log",
    "php-error.log", "logs/error_log", "logs/php_errorlog",
]
# Cadenas tipicas de un log de errores de PHP real, para no dar un falso
# positivo con paginas "catch-all" que devuelven 200 para cualquier ruta.
PHP_ERROR_LOG_MARKERS = (
    "php warning", "php fatal error", "php notice",
    "php deprecated", "php parse error", "stack trace:",
)
COMPOSER_PATHS = ["composer.json", "composer.lock"]

# Ficheros README genericos (varias extensiones/variantes de nombre), sin
# atarse a ningun CMS concreto: muchisimo software PHP (frameworks,
# librerias, paneles de administracion...) documenta aqui la version
# minima de PHP requerida, informacion valiosa que antes se perdia si el
# fichero no era exactamente el readme.html de WordPress.
README_PATHS = [
    "readme.html",
    "readme.txt",
    "README.txt",
    "readme.md",
    "README.md",
    "README",
    "readme",
]

# Rutas por defecto de WordPress: su sola presencia (200/301/302/403, es
# decir "no 404") ya es indicio de que la app corre sobre WordPress.
WORDPRESS_PATHS = [
    "wp-login.php",
    "wp-admin/",
    "wp-content/",
    "wp-includes/",
    "xmlrpc.php",
]

# Rutas por defecto de Drupal (D7 clasico y D8+ con prefijo core/), separadas
# en FUERTES (practicamente exclusivas de Drupal) y DEBILES (genericas,
# aparecen tambien en apps que no son Drupal - un solo hit aqui no basta).
DRUPAL_STRONG_PATHS = [
    "core/misc/drupal.js",
    "misc/drupal.js",
    "sites/default/settings.php",
]
DRUPAL_WEAK_PATHS = [
    "core/CHANGELOG.txt",
    "CHANGELOG.txt",   # muchisimo software no-Drupal tambien lo expone
    "user/login",       # ruta de login generica, no exclusiva de Drupal
]

# Directorios/ficheros genericos propios de instalaciones PHP, sin atarse a
# ningun CMS concreto. Un hallazgo aqui no implica por si solo un CMS, pero
# si aporta evidencia (variable segun la ruta) de que la app corre PHP.
PHP_GENERIC_PATHS = [
    "vendor/",
    "vendor/autoload.php",
    ".env",
    "includes/",
    "inc/",
    "cgi-bin/",
    "phpmyadmin/",
    "pma/",
    "admin/",
    "install/",
    "setup/",
    ".git/config",
]

# Subconjunto de PHP_GENERIC_PATHS que es evidencia FUERTE y especifica de
# PHP (no generica de cualquier stack web), usada tambien por
# has_direct_php_evidence para calcular "Usa PHP".
PHP_GENERIC_STRONG_SIGNALS = {"vendor/", "vendor/autoload.php", ".env"}

# --------------------------------------------------------------------------
# Favicon hashing (columna "Favicon")
# MD5 del contenido RAW de favicon.ico, comparado contra hashes por defecto
# de instalaciones sin personalizar. Fuente de los hashes: OWASP Favicon
# Database (https://community.owasp.org/favicons_database). Se usa MD5
# sobre los bytes crudos (no el mmh3/base64 de Shodan) porque son los
# valores verificables de esa fuente; un hash que no coincide no es
# evidencia de nada (favicon personalizado), solo una coincidencia es señal.
# --------------------------------------------------------------------------
FAVICON_MD5_HASHES = {
    # WordPress (varias versiones y temas por defecto)
    "fa54dbf2f61bd2e0188e47f5f578f736": "WordPress",
    "6cec5a9c106d45e458fc680f70df91b0": "WordPress (version obsoleta)",
    "b231ad66a2a9b0eb06f72c4c88973039": "WordPress",
    "e1e8bdc3ce87340ab6ebe467519cf245": "WordPress",
    "95103d0eabcd541527a86f23b636e794": "WordPress Multi-User (MU)",
    "e44d22b74f7ee4435e22062d5adf4a6a": "WordPress 2.x",
    "3ead5afa19537170bb980924397b70d6": "WordPress 3.x (Twenty Ten)",
    "28a122aa74f6929b0994fc544555c0b1": "WordPress 3.2-3.x (Twenty Eleven)",
    # Drupal
    "e6a9dc66179d8c9f34288b16a02f987e": "Drupal CMS (5.10)",
    "f0ee98b4394dfdab17c16245dd799204": "Drupal",
    "a4819787db1dabe1a6b669d5d6df3bfd": "Drupal 2.x-4.x",
    "b6341dfc213100c61db4fb8775878cec": "Drupal 7.x",
    # phpMyAdmin
    "02dd7453848213a7b5277556bcc46307": "phpMyAdmin (2.11.8.1 - pmd)",
    "d037ef2f629a22ddadcf438e6be7a325": "phpMyAdmin (2.11.8.1)",
    "531b63a51234bb06c9d77f219eb25553": "phpMyAdmin (4.6.x)",
    # Otras aplicaciones/CMS PHP con favicon por defecto reconocible
    "9187f6607b402df8bbc2aeb69a07bbca": "XOOPS",
    "389a8816c5b87685de7d8d5fec96c85b": "XOOPS cms",
    "c1201c47c81081c7f0930503cae7f71a": "vBulletin forum",
    "f425342764f8c356479d05daa7013c2f": "vBulletin forum",
    "740af61c776a3cb98da3715bdf9d3fc1": "vBulletin forum",
    "d7ac014e83b5c4a2dea76c50eaeda662": "vBulletin forum",
    "e2cac3fad9fa3388f639546f3ba09bc0": "Invision Power Services IP.Board",
    "83a1fd57a1e1684fafd6d2487290fdf5": "Pligg",
    "4cbb2cfc30a089b29cd06179f9cc82ff": "Dragonfly",
    "7214637a176079a335d7ac529011f4e4": "phpress",
    "bc18566dcc41a0ff503968f461c4995a": "Subrion CMS",
    "8718c2998236c796896b725f264092ee": "Typo3 6.1",
    "a456dd2bae5746beb68814a5ac977048": "phpSysInfo 3.0.7",
    "6e0c5b7979e9950125c71341e0960f65": "phpSysInfo 3.0.8-3.0.12",
    "ddcc65196f0bc63a90c885bd88ecbb81": "phpSysInfo 3.0.12-3.0.20, 3.1.0-3.1.4",
    "4b30eec86e9910e663b5a9209e9593b6": "phpldapadmin (1.1.0.5)",
    "90c244c893a963e3bb193d6043a347bd": "phpgroupware (0.9.16.012)",
    "d361075db94bb892ff3fb3717714b2da": "phpMyBackupPro",
    "368c15ac73f0096aa3daff8ff6f719f8": "Redaxscript 1.0-1.2.1",
    "2e9545474ee33884b5fb8a9a0b8806dd": "Ampache",
}

# Rutas habituales donde se publica el favicon
FAVICON_PATHS = ["favicon.ico"]

HEADERS_UA = {"User-Agent": "Mozilla/5.0 (PHP-Recon-Scan; authorized-pentest)"}

# --------------------------------------------------------------------------
# CVE-2026-109618 / CVE-2026-109619 (PHP web runtimes)
# Fuente: https://aws.amazon.com/es/security/security-bulletins/2026-143-aws/
# Clave = (major, minor) de la rama PHP; valor = (patch de la primera
# version corregida, texto de esa version). Las ramas 5.4-8.1 son EOL y no
# tienen parche disponible segun el boletin.
# --------------------------------------------------------------------------
AWS_BULLETIN_URL = "https://aws.amazon.com/es/security/security-bulletins/2026-143-aws/"
CVE_COLUMN_NAME = "CVE-2026-109618 / CVE-2026-109619"
PHP_CVE_FIXED_VERSIONS = {
    (8, 5): (12, "8.5.12"),
    (8, 4): (27, "8.4.27"),
    (8, 3): (36, "8.3.36"),
    (8, 2): (35, "8.2.35"),
}
PHP_EOL_NO_FIX_RANGE = ((5, 4), (8, 1))  # inclusive: 5.4 hasta 8.1



# Lock exclusivamente para que los prints de distintos hilos (mensajes de
# "[*] Escaneando ..." y la barra de progreso) no se corten entre si en la
# terminal. No tiene ninguna relacion con los datos que acaban en el Excel.
_print_lock = threading.Lock()


def log(msg: str):
    """Imprime por stderr de forma atomica entre hilos. Solo salida de terminal."""
    with _print_lock:
        print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_request(method, url, **kwargs):
    kwargs.setdefault("allow_redirects", True)
    try:
        return requests.request(
            method, url, timeout=TIMEOUT, verify=False,
            headers=HEADERS_UA, **kwargs
        )
    except requests.RequestException:
        return None


REDIRECT_CODES = (301, 302, 303, 304, 307, 308)

# Dominios de SSO/IdP corporativos contra los que no tiene sentido (ni es
# etico) lanzar fingerprinting: si la app redirige aqui, el activo real esta
# detras de autenticacion federada y se marca el hallazgo sin seguir probando.
SSO_DOMAINS = (
    "login.microsoftonline.com",
)


def is_sso_redirect(url: str) -> bool:
    """
    Compara por dominio exacto o subdominio real (host == sso o
    host.endswith('.' + sso)), nunca por subcadena, para evitar falsos
    positivos/negativos con dominios de typosquatting como
    'login.microsoftonline.com.evil.com' o 'evil-login.microsoftonline.com.com'.
    """
    try:
        host = urlparse(url).netloc.lower().split(":")[0]  # quitamos el puerto si lo hay
    except Exception:
        return False
    return any(host == sso or host.endswith("." + sso) for sso in SSO_DOMAINS)


def resolve_redirect_chain(url: str, max_redirects: int = 10):
    """
    Sigue manualmente las redirecciones (301/302/303/304/307/308) partiendo
    de `url`, devolviendo la URL final sobre la que deben lanzarse el resto
    de pruebas, y la cadena completa de saltos para dejarla documentada.
    Se hace a mano (allow_redirects=False) en lugar de delegar en requests
    para poder registrar cada salto y detectar bucles.
    """
    chain = [url]
    current = url
    visited = {url}

    for _ in range(max_redirects):
        resp = safe_request("GET", current, allow_redirects=False)
        if resp is None:
            break

        if resp.status_code not in REDIRECT_CODES:
            break

        location = resp.headers.get("Location")
        if not location:
            # p.ej. 304 Not Modified sin Location: no hay a donde saltar
            break

        next_url = urljoin(current, location)
        if next_url in visited:
            chain.append(f"{next_url} (bucle detectado, se detiene aqui)")
            break

        chain.append(next_url)
        visited.add(next_url)
        current = next_url

        if is_sso_redirect(current):
            # No seguimos mas saltos ni lanzamos peticiones extra contra el IdP.
            break

    return current, chain


# --------------------------------------------------------------------------
# Deteccion de "soft 404" / catch-all (anti falsos positivos)
# --------------------------------------------------------------------------
# Muchos de los check_* comprueban rutas por defecto mirando solo el codigo
# de estado (200/301/302/403 = "existe"). Eso falla con servidores que
# devuelven 200/403 para CUALQUIER ruta (SPA que sirve siempre index.html,
# WAF que responde igual a todo, pagina de error personalizada con 200...):
# en ese caso TODAS las rutas de TODOS los CMS "existirian" a la vez, dando
# falsos positivos en cascada. get_baseline_response() pide una ruta
# practicamente garantizado que no existe, una sola vez por activo, y
# path_looks_real() descarta como catch-all cualquier hit cuyo status y
# longitud de contenido coincidan con ese baseline.
def get_baseline_response(base_url: str):
    """
    Pide una ruta aleatoria que no deberia existir en ninguna instalacion
    real, para usarla como referencia de "respuesta generica" (catch-all)
    del servidor. Se calcula una vez por activo y se reutiliza en todos
    los check_* que recorren listas de rutas por defecto.
    """
    nonce = f"__recon_baseline_{os.urandom(6).hex()}__/no-existe.xyz"
    url = urljoin(base_url.rstrip("/") + "/", nonce)
    resp = safe_request("GET", url)
    if resp is None:
        return None
    return {"status": resp.status_code, "length": len(resp.content or b"")}


def path_looks_real(resp, baseline) -> bool:
    """
    True si la respuesta a una ruta por defecto parece un hit real y no un
    catch-all: o bien no hay baseline disponible (no se pudo calcular, se
    sigue con el comportamiento anterior), o bien el status/longitud no
    coincide con la respuesta generica del servidor para rutas inexistentes.
    Tolerancia de 5 bytes en la longitud para no fallar por contadores o
    timestamps variables en paginas de error dinamicas.
    """
    if baseline is None:
        return True
    if resp.status_code != baseline["status"]:
        return True
    longitud = len(resp.content or b"")
    return abs(longitud - baseline["length"]) > 5


def find_existing_paths(base_url: str, paths: list, baseline=None) -> list:
    """
    Helper compartido: para cada ruta en `paths`, hace GET y la considera
    "existente" si el status es 200/301/302/403 Y (si hay baseline) no
    parece un catch-all generico. Centraliza una logica que antes estaba
    duplicada casi igual en check_wordpress, check_drupal y
    check_php_default_dirs.
    """
    encontradas = []
    for path in paths:
        url = urljoin(base_url.rstrip("/") + "/", path)
        resp = safe_request("GET", url)
        if resp is None or resp.status_code not in (200, 301, 302, 403):
            continue
        if not path_looks_real(resp, baseline):
            continue
        encontradas.append(path)
    return encontradas


# --------------------------------------------------------------------------
# Tecnicas individuales
# --------------------------------------------------------------------------
def check_headers(base_url: str, home_resp=None) -> str:
    """X-Powered-By / Server headers"""
    resp = home_resp if home_resp is not None else safe_request("GET", base_url)
    if resp is None:
        return "ERROR - sin respuesta"
    xpb = resp.headers.get("X-Powered-By", "")
    server = resp.headers.get("Server", "")
    partes = []
    if xpb:
        partes.append(f"X-Powered-By: {xpb}")
    if server:
        partes.append(f"Server: {server}")
    return " | ".join(partes) if partes else "No expuesto"


def check_cookies(base_url: str, home_resp=None) -> str:
    """Nombre y forma de las cookies de sesion"""
    resp = home_resp if home_resp is not None else safe_request("GET", base_url)
    if resp is None:
        return "ERROR - sin respuesta"
    set_cookie = resp.headers.get("Set-Cookie", "")
    cookies_found = []
    for c in resp.cookies:
        cookies_found.append(f"{c.name}={c.value[:12]}...")
    if not cookies_found and set_cookie:
        cookies_found.append(set_cookie[:80])
    return " | ".join(cookies_found) if cookies_found else "Sin cookies en respuesta inicial"


def check_php_default(base_url: str, baseline=None) -> str:
    """
    Columna "PHP default": comprueba rutas y ficheros que solo aparecen en
    instalaciones PHP por defecto o mal configuradas:
      1) phpinfo() expuesto en las rutas habituales (phpinfo.php, info.php...).
      2) Log de errores de PHP expuesto en la raiz (error_log, php_errorlog...),
         cuando log_errors=On y error_log no se reubico fuera del document
         root - information disclosure critico ademas de senal de PHP.
      3) Ficheros README (varias extensiones: .html/.txt/.md/sin extension),
         identificando el fichero accesible y, si lo expresa, la version
         minima de PHP que requiere la aplicacion - util tanto si es
         WordPress como si es cualquier otro software PHP.

    Cada hallazgo es UNA linea dentro de la misma celda (separadas por salto
    de linea, no por " | "), para no comprimir en una sola frase la
    informacion de varios ficheros distintos cuando hay mas de uno.

    `baseline` (de get_baseline_response) se usa en el bloque de README
    para no confundir un servidor "catch-all" (200 para cualquier ruta) con
    que de verdad existen varios README distintos.
    """
    hallazgos = []

    for path in PHPINFO_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        resp = safe_request("GET", url)
        if resp is not None and resp.status_code == 200 and "phpinfo" in resp.text.lower():
            match = re.search(r"PHP Version\s*</td>\s*<td[^>]*>\s*(\d+(?:\.\d+)*)", resp.text, re.IGNORECASE)
            version = match.group(1) if match else "version no parseada"
            hallazgos.append(f"{path} -> EXPUESTO ({version})")

    for path in PHP_ERROR_LOG_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        resp = safe_request("GET", url)
        if resp is not None and resp.status_code == 200 and len(resp.text.strip()) > 0:
            cuerpo = resp.text.lower()
            if any(marker in cuerpo for marker in PHP_ERROR_LOG_MARKERS):
                # Marcador especifico de PHP en el contenido: evidencia fuerte,
                # se muestra siempre aunque coincida con el baseline (un
                # catch-all generico no va a contener "PHP Fatal error" por
                # casualidad).
                hallazgos.append(f"{path} -> EXPUESTO (log de errores PHP confirmado)")
            elif path_looks_real(resp, baseline):
                # Responde 200 con contenido pero sin los marcadores tipicos:
                # lo dejamos constar igualmente, sin afirmar que es un log
                # real, pero solo si no parece la respuesta catch-all
                # generica del servidor (si no, serian 6 lineas de ruido
                # identicas en cada activo con ese tipo de servidor).
                hallazgos.append(f"{path} -> accesible (sin confirmar como log PHP)")

    for path in README_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        resp = safe_request("GET", url)
        if resp is None or resp.status_code != 200 or not resp.text.strip():
            continue
        if not path_looks_real(resp, baseline):
            continue
        min_php = extract_min_php_from_generic_readme(resp.text)
        if min_php:
            hallazgos.append(f"{path} -> accesible | PHP minimo requerido: {min_php}")
        else:
            hallazgos.append(f"{path} -> accesible (sin version minima de PHP detectada)")

    return "\n".join(hallazgos) if hallazgos else "Ninguno expuesto"


def check_composer(base_url: str) -> str:
    """Prueba composer.json / composer.lock expuestos"""
    hallazgos = []
    for path in COMPOSER_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        resp = safe_request("GET", url)
        if resp is not None and resp.status_code == 200 and len(resp.text) > 20:
            php_req = re.search(r'"php"\s*:\s*"([^"]+)"', resp.text)
            extra = f" (php requirement: {php_req.group(1)})" if php_req else ""
            hallazgos.append(f"{path} -> EXPUESTO{extra}")
    return " | ".join(hallazgos) if hallazgos else "No expuestos"


# --------------------------------------------------------------------------
# CVE-2026-109618 / CVE-2026-109619 (PHP) - logica local, sin red, basada
# en el boletin de AWS. No requiere ninguna peticion adicional: reutiliza
# lo que ya se detecto en las columnas del propio Excel.
# --------------------------------------------------------------------------
def parse_version_tuple(version_str: str):
    """'7.4.3' -> (7, 4, 3). '8.1' -> (8, 1, 0). None si no hay match."""
    if not version_str:
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not m:
        return None
    major, minor, patch = m.groups()
    return (int(major), int(minor), int(patch) if patch else 0)


def extract_php_version_from_result(result: dict):
    """
    Busca una version de PHP ya detectada en las columnas del propio
    resultado, por orden de fiabilidad (de mas a menos directa), y
    devuelve (version, fuente) o (None, None) si no se encontro ninguna.
    """
    # 1) phpinfo expuesto: "phpinfo.php -> EXPUESTO (7.4.3)"
    phpinfo_col = result.get("PHP default", "") or ""
    m = re.search(r"EXPUESTO\s*\(([\d]+\.[\d]+(?:\.[\d]+)?)\)", phpinfo_col)
    if m:
        return m.group(1), "phpinfo expuesto"

    # 2) Cabecera X-Powered-By: PHP/7.4.3
    headers_col = result.get("Cabeceras HTTP (X-Powered-By/Server)", "") or ""
    m = re.search(r"PHP/([\d]+\.[\d]+(?:\.[\d]+)?)", headers_col, re.IGNORECASE)
    if m:
        return m.group(1), "cabecera X-Powered-By"

    # 3) Salida de nmap (script http-php-version -> "Version: 7.4.3", o
    #    banner de servicio con "PHP/7.4.3")
    nmap_col = result.get("Nmap -sV (servicios/tecnologias + PHP)", "") or ""
    m = re.search(r"Version:\s*([\d]+\.[\d]+(?:\.[\d]+)?)", nmap_col, re.IGNORECASE)
    if not m:
        m = re.search(r"PHP/([\d]+\.[\d]+(?:\.[\d]+)?)", nmap_col, re.IGNORECASE)
    if m:
        return m.group(1), "nmap"

    # 4) WhatWeb: PHP[7.4.3]
    whatweb_col = result.get("WhatWeb", "") or ""
    m = re.search(r"PHP\[([\d]+\.[\d]+(?:\.[\d]+)?)", whatweb_col, re.IGNORECASE)
    if m:
        return m.group(1), "whatweb"

    return None, None


def check_php_cve(result: dict) -> str:
    """
    Contrasta la version de PHP detectada (si la hay) contra el boletin de
    AWS para CVE-2026-109618 / CVE-2026-109619.
    """
    version_str, source = extract_php_version_from_result(result)
    if not version_str:
        return "No se pudo determinar la version de PHP para contrastarla"

    version = parse_version_tuple(version_str)
    if version is None:
        return f"No se pudo interpretar la version detectada ({version_str})"

    major, minor, patch = version
    branch = (major, minor)

    if branch in PHP_CVE_FIXED_VERSIONS:
        fix_patch, fix_label = PHP_CVE_FIXED_VERSIONS[branch]
        if patch < fix_patch:
            return (
                f"VULNERABLE - CVE-2026-109618 / CVE-2026-109619 "
                f"(detectado {version_str} via {source}; corregido en {fix_label})"
            )
        return f"No vulnerable - {version_str} >= {fix_label} (via {source})"

    eol_start, eol_end = PHP_EOL_NO_FIX_RANGE
    if eol_start <= (major, minor) <= eol_end:
        return (
            f"VULNERABLE (rama EOL {eol_start[0]}.{eol_start[1]}-{eol_end[0]}.{eol_end[1]}, "
            f"sin parche disponible) - CVE-2026-109619 (mitigacion interina) / "
            f"CVE-2026-109618 (sin fix) - detectado {version_str} via {source}"
        )

    if (major, minor) > max(PHP_CVE_FIXED_VERSIONS.keys()):
        return f"Version {version_str} no contemplada en el boletin AWS 2026-143 (posterior, verificar manualmente)"

    return f"Version {version_str} anterior al rango cubierto por el boletin AWS 2026-143 (verificar manualmente)"


def extract_min_php_from_readme(readme_text: str):
    """
    El readme.html real del nucleo de WordPress expresa el requisito de PHP
    como HTML, tipicamente:
      <li><a href="https://www.php.net/">PHP</a> version <strong>7.4</strong> or greater.</li>
    (a veces hay dos <li> de este tipo: requisito minimo y version
    recomendada; nos quedamos con el primero, que es el minimo).
    Se intenta primero contra ese patron HTML exacto y, si no aparece
    (instalaciones antiguas o ligeramente distintas), se cae a una busqueda
    sobre el texto con las etiquetas ya eliminadas.
    """
    # 1) Patron HTML tal cual lo genera WordPress
    m = re.search(
        r"PHP</a>\s*version\s*<strong>(\d+(?:\.\d+)*)</strong>",
        readme_text, re.IGNORECASE,
    )
    if m:
        return m.group(1)

    # 2) Fallback: quitamos etiquetas HTML y buscamos en texto plano
    plano = re.sub(r"<[^>]+>", " ", readme_text)
    plano = re.sub(r"\s+", " ", plano)
    m = re.search(
        r"PHP\s+version\s+(\d+(?:\.\d+)*)\s+or\s+(?:greater|higher)",
        plano, re.IGNORECASE,
    )
    return m.group(1) if m else None


def extract_min_php_from_generic_readme(readme_text: str):
    """
    Busca la version minima de PHP requerida en un README generico de
    CUALQUIER aplicacion PHP (no solo WordPress), probando varias formas
    habituales de expresarlo, de mas a menos especifica:
      - El patron HTML propio de WordPress (reutiliza extract_min_php_from_readme,
        por si el README no es de WP pero usa un formato similar).
      - Cabecera de readme.txt de plugins/temas WP: "Requires PHP: 7.4".
      - "Requires PHP >= 7.4" / "requires php 7.4 or higher".
      - "PHP >= 7.4" / "PHP: >=7.4" (badges y tablas de requisitos).
      - "PHP minimo: 7.4" / "PHP minimum version: 7.4".
    Se exige siempre la palabra "php" pegada al numero de version para no
    extraer por error la version del propio software (que tambien suele
    aparecer en un README) en lugar de la de PHP.
    """
    m_wp = extract_min_php_from_readme(readme_text)
    if m_wp:
        return m_wp

    plano = re.sub(r"<[^>]+>", " ", readme_text)
    plano = re.sub(r"\s+", " ", plano)

    patrones = [
        r"Requires\s+PHP\s*:?\s*>?=?\s*(\d+(?:\.\d+)*)",
        r"PHP\s*(?:minimo|minimum)(?:\s+version)?\s*:?\s*(\d+(?:\.\d+)*)",
        r"PHP\s*:?\s*>=\s*(\d+(?:\.\d+)*)",
        r"PHP\s+(\d+(?:\.\d+)*)\s+or\s+(?:greater|higher|later|newer)",
        r"requires?\s+php\s+(\d+(?:\.\d+)*)",
    ]
    for patron in patrones:
        m = re.search(patron, plano, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def check_wordpress(base_url: str, home_resp=None, baseline=None) -> str:
    """
    Detecta si la app usa WordPress probando sus rutas por defecto, e
    intenta identificar la version concreta mirando, por orden, en:
      1) readme.html             -> "Version X.X" + PHP minimo requerido
      2) wp-includes/version.php -> $wp_version = 'X.X' (y tambien
         $required_php_version = 'X.X', otra fuente de PHP minimo) - solo
         da algo si el servidor esta mal configurado y sirve el .php como
         texto plano en vez de ejecutarlo.
      3) <meta name="generator"> en la home (solo version de WordPress;
         WordPress no expone aqui ningun dato de PHP)
      4) generator tag del feed RSS /feed/ (idem: solo version de WordPress)
    La version de WordPress se queda con la primera que consigue extraer;
    el PHP minimo requerido se intenta en las DOS fuentes que lo llevan
    (readme.html y wp-includes/version.php) y se queda con la primera que
    responda, indicando siempre de que fichero salio el dato.

    `baseline` (de get_baseline_response) descarta rutas que en realidad
    son un catch-all generico del servidor; `home_resp` evita repetir el
    GET a la home que ya hicieron check_headers/check_cookies.
    """
    # 1) Rutas por defecto de WordPress, descartando catch-alls via baseline
    evidence_paths = find_existing_paths(base_url, WORDPRESS_PATHS, baseline)
    detected = bool(evidence_paths)

    version = None
    version_source = None
    php_min_requerido = None
    php_min_fuente = None

    # 2) readme.html: version de WordPress + PHP minimo requerido por esa
    #    version del core. Se exige que el contenido mencione "wordpress"
    #    (no solo que el fichero exista con 200): un readme.html generico
    #    de otro software tambien puede traer una linea "Version X.X" y
    #    daria un falso positivo si solo mirasemos el status code.
    resp = safe_request("GET", urljoin(base_url.rstrip("/") + "/", "readme.html"))
    if resp is not None and resp.status_code == 200 and "wordpress" in resp.text.lower():
        detected = True
        m = re.search(r"Version\s+(\d+(?:\.\d+)*)", resp.text, re.IGNORECASE)
        if m:
            version = m.group(1)
            version_source = "readme.html"
        php_min_requerido = extract_min_php_from_readme(resp.text)
        if php_min_requerido:
            php_min_fuente = "readme.html"

    # 3) wp-includes/version.php (solo da algo si el servidor esta mal
    #    configurado y sirve el codigo fuente PHP en vez de ejecutarlo).
    #    Ademas de $wp_version, este fichero trae $required_php_version,
    #    una segunda fuente (mas exacta cuando esta disponible) del PHP
    #    minimo requerido por esa version de WordPress.
    resp = safe_request("GET", urljoin(base_url.rstrip("/") + "/", "wp-includes/version.php"))
    if resp is not None and resp.status_code == 200:
        if version is None:
            m = re.search(r"\$wp_version\s*=\s*['\"](\d+(?:\.\d+)*(?:-[\w]+)?)['\"]", resp.text)
            if m:
                detected = True
                version = m.group(1)
                version_source = "wp-includes/version.php"
        if php_min_requerido is None:
            m_php = re.search(r"\$required_php_version\s*=\s*['\"](\d+(?:\.\d+)*)['\"]", resp.text)
            if m_php:
                detected = True
                php_min_requerido = m_php.group(1)
                php_min_fuente = "wp-includes/version.php"

    # 4) Meta generator de la home (reutiliza home_resp si ya se pidio)
    if version is None:
        resp = home_resp if home_resp is not None else safe_request("GET", base_url)
        if resp is not None and resp.status_code == 200:
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+(\d+(?:\.\d+)*)',
                resp.text, re.IGNORECASE,
            )
            if m:
                detected = True
                version = m.group(1)
                version_source = "meta generator (home)"

    # 5) Generator tag del feed RSS
    if version is None:
        resp = safe_request("GET", urljoin(base_url.rstrip("/") + "/", "feed/"))
        if resp is not None and resp.status_code == 200:
            m = re.search(r"wordpress\.org/\?v=(\d+(?:\.\d+)*)", resp.text, re.IGNORECASE)
            if m:
                detected = True
                version = m.group(1)
                version_source = "feed RSS generator"

    if not detected:
        return "No detectado"

    php_min_sufijo = (
        f" | PHP minimo requerido ({php_min_fuente}): {php_min_requerido}"
        if php_min_requerido else ""
    )

    if version:
        # Formato pedido: "version - fichero donde se ha identificado"
        return f"{version} - {version_source}{php_min_sufijo}"

    rutas = ", ".join(evidence_paths[:3]) if evidence_paths else "indicios generales"
    return f"WordPress detectado (version no identificada) - rutas: {rutas}{php_min_sufijo}"


# --------------------------------------------------------------------------
# Deteccion de Drupal (rutas por defecto + cookies + cabeceras), con un
# modelo de confianza FUERTE/DEBIL para evitar falsos positivos:
#   - Una sola ruta FUERTE (practicamente exclusiva de Drupal) ya confirma.
#   - Las rutas DEBILES (genericas: "CHANGELOG.txt", "user/login"...)
#     existen en muchisimo software que no es Drupal, asi que un solo hit
#     ahi NO basta: se exige >= 2 rutas debiles distintas, o 1 ruta debil +
#     una corroboracion de cookie/cabecera especifica de Drupal.
#   - check_drupal devuelve (bool detectado, str confianza "strong"/"weak"/
#     "none"), que luego usa reconcile_cms_detections() para no marcar
#     "Si" simultaneamente en WordPress y Drupal en un mismo activo cuando
#     solo uno tiene evidencia fuerte y el otro llega por rutas genericas.
# --------------------------------------------------------------------------
def check_drupal(base_url: str, home_resp=None, baseline=None) -> str:
    """
    Columna "Drupal": lista TODOS los recursos/marcadores por defecto de
    Drupal identificados (una linea por hallazgo, igual que "PHP default"),
    para que quede visible por que "Usa Drupal" acaba siendo "Si" o "No"
    en lugar de un simple booleano sin justificar.

    Se muestran, si aparecen, en este orden:
      1) Rutas FUERTES (practicamente exclusivas de Drupal: core/misc/
         drupal.js, sites/default/settings.php...) - cualquiera de ellas
         ya basta para considerar Drupal confirmado.
      2) Marcadores especificos (cookie SESS/SSESS, cabecera X-Generator:
         Drupal, X-Drupal-Cache/X-Drupal-Dynamic-Cache) - igual de fuertes
         que una ruta especifica.
      3) Rutas DEBILES (genericas: CHANGELOG.txt, user/login) - aparecen
         en muchisimo software que no es Drupal, asi que por si solas (una
         sola, sin nada mas) NO se consideran suficientes; se muestran de
         todas formas para que se vea que se encontraron, y derive_drupal_confidence()
         es quien decide si son o no suficientes para "Usa Drupal".

    `baseline` descarta rutas que en realidad son un catch-all generico
    del servidor; `home_resp` evita repetir el GET a la home.
    """
    hallazgos = []

    # Nota: se etiqueta cada linea con [FUERTE] o [GENERICA] en mayusculas
    # y en una forma fija (sin variarla por concordancia de genero en
    # castellano, p.ej. "especifica" vs "especifico"), para que
    # derive_drupal_confidence() pueda reconocerla de forma inequivoca con
    # una simple busqueda de subcadena.
    strong_paths = find_existing_paths(base_url, DRUPAL_STRONG_PATHS, baseline)
    for path in strong_paths:
        hallazgos.append(f"{path} [FUERTE: ruta especifica de Drupal]")

    resp = home_resp if home_resp is not None else safe_request("GET", base_url)
    if resp is not None:
        cookie_names = [c.name for c in resp.cookies]
        set_cookie_header = resp.headers.get("Set-Cookie", "")

        if any(re.match(r"S?SESS[0-9a-fA-F]{32}$", name) for name in cookie_names) or \
           re.search(r"\bS?SESS[0-9a-fA-F]{32}=", set_cookie_header):
            hallazgos.append("Cookie de sesion SESS/SSESS [FUERTE: marcador especifico de Drupal]")

        x_generator = resp.headers.get("X-Generator", "")
        if "drupal" in x_generator.lower():
            hallazgos.append(f"Cabecera X-Generator: {x_generator} [FUERTE: marcador especifico]")

        if "X-Drupal-Cache" in resp.headers or "X-Drupal-Dynamic-Cache" in resp.headers:
            hallazgos.append("Cabecera X-Drupal-Cache/X-Drupal-Dynamic-Cache [FUERTE: marcador especifico]")

    weak_paths = find_existing_paths(base_url, DRUPAL_WEAK_PATHS, baseline)
    for path in weak_paths:
        hallazgos.append(f"{path} [GENERICA: no concluyente por si sola]")

    return "\n".join(hallazgos) if hallazgos else "No detectado"


def derive_drupal_confidence(drupal_col: str):
    """
    Deriva (detectado, confianza) a partir del texto ya calculado en la
    columna "Drupal" (check_drupal), sin lanzar peticiones nuevas:
      - "strong" si hay al menos una linea etiquetada [FUERTE].
      - "weak" si solo hay lineas [GENERICA], y ademas se exigen >= 2 (una
        sola ruta generica, que aparece en multitud de software que no es
        Drupal, no basta para marcar "Usa Drupal" = "Si").
    """
    if not drupal_col or drupal_col in ("No detectado", "-"):
        return False, "none"
    lineas = drupal_col.split("\n")
    if any("[FUERTE" in linea for linea in lineas):
        return True, "strong"
    genericas = [l for l in lineas if "[GENERICA" in l]
    if len(genericas) >= 2:
        return True, "weak"
    return False, "none"


def derive_wp_confidence(wp_col: str):
    """
    Deriva (detectado, confianza) a partir del texto ya calculado en la
    columna "WordPress" (check_wordpress), sin lanzar peticiones nuevas:
      - "strong" si se identifico una version concreta (formato "X - fichero")
        o via meta generator/feed, especificos de WordPress.
      - "weak" si solo se detecto por la existencia de rutas por defecto
        sin version confirmada, para tratarlo igual que el resto de CMS en
        la reconciliacion de falsos positivos cruzados.
    """
    if not wp_col or wp_col in ("No detectado", "-"):
        return False, "none"
    if "version no identificada" in wp_col:
        return True, "weak"
    return True, "strong"


def reconcile_cms_detections(result: dict, confidences: dict):
    """
    Evita que un mismo activo quede marcado con "Si" en WordPress y Drupal
    a la vez por colision de rutas genericas: si ambos salen "Si" y al
    menos uno tiene confianza "strong", se degrada a "No" el que solo
    llego a "Si" con confianza "weak". Si los dos tienen confianza
    "strong" simultaneamente, se dejan ambos: eso ya no es colision de
    rutas genericas, es una coexistencia real a reportar y no se debe
    ocultar.
    """
    positivos = [col for col in confidences if result.get(col) == "Si"]
    if len(positivos) <= 1:
        return
    fuertes = [col for col in positivos if confidences[col] == "strong"]
    if not fuertes:
        return
    for col in positivos:
        if col not in fuertes:
            result[col] = "No"


def check_php_default_dirs(base_url: str, baseline=None) -> str:
    """
    Prueba un listado de directorios/ficheros genericos propios de
    instalaciones PHP (vendor/, .env, includes/, phpmyadmin/, etc.), sin
    atarse a ningun CMS concreto. Complementa a check_php_default y
    check_composer, que ya cubren sus propios casos especificos.

    `baseline` descarta rutas que en realidad son un catch-all generico
    del servidor (si no se descartaran, un servidor que responde 200/403
    a cualquier ruta marcaria TODOS estos directorios como "expuestos").
    """
    hallazgos = find_existing_paths(base_url, PHP_GENERIC_PATHS, baseline)
    return ", ".join(hallazgos) if hallazgos else "Ninguno expuesto"


def check_favicon(base_url: str) -> str:
    """
    Columna "Favicon": descarga favicon.ico y compara el MD5 de su
    contenido crudo (bytes, no texto) contra FAVICON_MD5_HASHES, un
    listado de hashes por defecto/sin personalizar de CMS y software
    conocidos (fuente: OWASP Favicon Database). Un hash que SI coincide es
    una senal fuerte (ese favicon exacto, sin tocar, es el de esa
    instalacion); un hash que NO coincide no es evidencia de nada: lo mas
    probable es que el sitio tenga un favicon propio/personalizado.
    """
    for path in FAVICON_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        resp = safe_request("GET", url)
        if resp is None or resp.status_code != 200 or not resp.content:
            continue
        md5_hash = hashlib.md5(resp.content).hexdigest()
        software = FAVICON_MD5_HASHES.get(md5_hash)
        if software:
            return f"CMS/software detectado: {software} (MD5: {md5_hash})"
        return f"Favicon propio/no reconocido (MD5: {md5_hash})"
    return "Sin favicon.ico accesible"


# --------------------------------------------------------------------------
# Flags de inteligencia derivados ("Usa WP" / "Usa Drupal" / "Usa PHP").
# "Usa WP" se deriva de la columna "WordPress" ya calculada (ver
# derive_wp_confidence, mas arriba); Drupal lanza su propia comprobacion
# (ver check_drupal).
# --------------------------------------------------------------------------


def has_direct_php_evidence(result: dict) -> bool:
    """
    Evidencia DIRECTA de PHP ya recopilada en otras columnas del propio
    resultado (sin lanzar peticiones nuevas): version de PHP detectada,
    phpinfo/log de errores PHP expuesto, un README que declara una version
    minima de PHP requerida, composer.json/lock expuestos, un favicon que
    coincide con un hash de CMS/software conocido (todas las entradas de
    FAVICON_MD5_HASHES son software PHP), la palabra "php" en la salida de
    nmap/whatweb, o alguno de los directorios/ficheros genericos de PHP
    marcados como senal fuerte (vendor/, .env...).
    """
    version_str, _source = extract_php_version_from_result(result)
    if version_str:
        return True

    phpinfo_col = result.get("PHP default", "") or ""
    if "EXPUESTO" in phpinfo_col or "PHP minimo requerido" in phpinfo_col:
        return True

    composer_col = result.get("composer.json/lock expuestos", "") or ""
    if "EXPUESTO" in composer_col:
        return True

    favicon_col = result.get("Favicon", "") or ""
    if favicon_col.startswith("CMS/software detectado"):
        return True

    for col in ("Cabeceras HTTP (X-Powered-By/Server)",
                "Nmap -sV (servicios/tecnologias + PHP)",
                "WhatWeb"):
        valor = result.get(col, "") or ""
        if re.search(r"\bphp\b", valor, re.IGNORECASE):
            return True

    dirs_col = result.get("Directorios PHP por defecto", "") or ""
    hallados = {d.strip() for d in dirs_col.split(",")}
    if hallados & PHP_GENERIC_STRONG_SIGNALS:
        return True

    return False


def flag_php(result: dict) -> str:
    """
    'Usa PHP' = Si si se detecto WordPress o Drupal (ambos son PHP por
    definicion), O si hay evidencia directa de PHP ya recopilada en otras
    columnas.
    """
    cms_flags = ("Usa WP", "Usa Drupal")
    if any(result.get(flag) == "Si" for flag in cms_flags):
        return "Si"
    return "Si" if has_direct_php_evidence(result) else "No"


def run_cmd(cmd: list, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout or "") + (result.stderr or "")
        return output.strip()[:2000] if output.strip() else "Sin salida"
    except subprocess.TimeoutExpired:
        return "ERROR - timeout"
    except FileNotFoundError:
        return "N/A - herramienta no encontrada"
    except Exception as e:
        return f"ERROR - {e}"


def run_nmap(host_port: str) -> str:
    """
    Lanza nmap con -sV (deteccion de version de servicios: Apache, Nginx,
    OpenSSL, etc.) combinado con el script http-php-version, para que en
    una misma celda queden tanto la version de PHP como el resto de
    tecnologias/versiones detectadas en los puertos escaneados.
    """
    if not tool_exists("nmap"):
        return "N/A - nmap no instalado"

    out = run_cmd(
        ["nmap", "-sV", "--version-intensity", "5", "-p", "80,443",
         "--script", "http-php-version", host_port],
        timeout=150,  # -sV alarga el escaneo, le damos mas margen que a un nmap simple
    )

    relevant = []
    in_php_script_block = False
    for raw_line in out.splitlines():
        line = raw_line.strip()
        low = line.lower()

        # Lineas de puerto con servicio/version detectados por -sV
        # (ej: "80/tcp open  http  Apache httpd 2.4.41 ((Ubuntu))")
        if "/tcp" in low or "/udp" in low:
            relevant.append(line)
            in_php_script_block = False
            continue

        # Inicio del bloque de salida del script http-php-version
        # (ej: "| http-php-version:")
        if "php" in low:
            relevant.append(line)
            in_php_script_block = line.startswith("|") and not line.startswith("|_")
            continue

        # Lineas de continuacion del script NSE anterior (empiezan por | o |_),
        # como "|_  Version: 7.4.3", que es donde realmente viene el dato util
        if in_php_script_block and line.startswith(("|", "|_")):
            relevant.append(line)
            if line.startswith("|_"):
                in_php_script_block = False
            continue

        # NOTA: la linea "Service Info" que nmap añade con -sV (SO, CPE, etc.)
        # se descarta a proposito: no aporta valor para el fingerprinting de
        # PHP/servicios y no debe escribirse en el Excel.

    # Un salto de linea por cada servicio/hallazgo detectado, en lugar de
    # concatenarlo todo en una sola linea: mas legible cuando la app expone
    # varios puertos/servicios (ej: 80 y 443 con versiones distintas).
    return "\n".join(relevant) if relevant else (out[:300] if out else "Sin salida")


# Secuencias de color ANSI, con o sin el caracter ESC real (whatweb a veces
# las emite aunque no haya terminal, y segun como se capture la salida el
# byte ESC (\x1b) se pierde dejando solo literales tipo "[1m", "[0m]").
_ANSI_WITH_ESC_RE = re.compile(r"\x1b\[[0-9;]*m")
_ANSI_BARE_CODE_RE = re.compile(r"\[\d{1,3}(?:;\d{1,3})*m\]?")


def strip_ansi(text: str) -> str:
    text = _ANSI_WITH_ESC_RE.sub("", text)
    text = _ANSI_BARE_CODE_RE.sub("", text)
    return text


# Plugins de whatweb que NO son utiles para el fingerprinting de
# servidor/tecnologias (ruido): se descartan al filtrar la salida.
_WHATWEB_NOISE_PLUGINS = {
    "ip", "country", "title", "email", "redirectlocation",
    "uncommonheaders", "via-proxy", "allenum", "summary",
    "cookies", "x-frame-options", "strict-transport-security",
}


def _split_top_level(text: str, sep: str = ",") -> list:
    """Divide por comas que esten FUERA de corchetes, respetando que
    whatweb anide varios [valor] seguidos para un mismo plugin
    (ej: Country[UNITED STATES][US])."""
    parts, current, depth = [], [], 0
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_whatweb_output(raw: str) -> str:
    """
    Limpia los codigos ANSI y se queda solo con los plugins relevantes de
    servidor/tecnologias (Apache, nginx, PHP, HTTPServer, X-Powered-By,
    CMS, frameworks JS, etc.), descartando ruido como IP, Country, Title...
    """
    text = strip_ansi(raw).strip()
    if not text:
        return "Sin salida"

    # La URL y el codigo de estado ([200 OK]) van al principio de la linea;
    # el resto, tras el primer "] ", son los plugins detectados.
    marker = "] "
    idx = text.find(marker)
    plugins_part = text[idx + len(marker):] if idx != -1 else text

    tokens = _split_top_level(plugins_part)
    utiles = []
    for token in tokens:
        plugin_name = token.split("[", 1)[0].strip().lower()
        if plugin_name in _WHATWEB_NOISE_PLUGINS:
            continue
        utiles.append(token)

    return ", ".join(utiles) if utiles else "Sin tecnologias relevantes detectadas"


def run_whatweb(base_url: str) -> str:
    if not tool_exists("whatweb"):
        return "N/A - whatweb no instalado"
    out = run_cmd(
        ["whatweb", "-a", "3", "--no-errors", "--color=never", base_url],
        timeout=60,
    )
    cleaned = parse_whatweb_output(out)
    return cleaned[:800]


def run_nikto(base_url: str) -> str:
    if not tool_exists("nikto"):
        return "N/A - nikto no instalado"
    out = run_cmd(["nikto", "-h", base_url, "-Tuning", "9"], timeout=180)
    lines = [l for l in out.splitlines() if "php" in l.lower()]
    return " | ".join(lines[:10]) if lines else "Sin hallazgos PHP relevantes"


def run_nuclei(base_url: str) -> str:
    if not tool_exists("nuclei"):
        return "N/A - nuclei no instalado"
    out = run_cmd(["nuclei", "-u", base_url, "-t", "technologies/", "-silent"], timeout=180)
    return out[:800] if out else "Sin hallazgos"


# --------------------------------------------------------------------------
# Orquestacion por activo
# --------------------------------------------------------------------------
def extract_host_port(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else url


def scan_target(url: str, full: bool) -> dict:
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http"):
        url = "http://" + url

    log(f"[*] Escaneando {url} ...")

    final_url, chain = resolve_redirect_chain(url)
    if len(chain) > 1:
        redirect_summary = " -> ".join(chain)
        log(f"    [>] Redirigido: {redirect_summary}")
    else:
        redirect_summary = "Sin redireccion"

    if is_sso_redirect(final_url):
        log(
            f"    [i] {url} redirige a SSO corporativo ({final_url}) "
            f"- se omiten el resto de pruebas, continuo con el siguiente activo"
        )
        omitido = "-"
        # Para SSO no mostramos la URI completa (puede llevar parametros de
        # OAuth largos e irrelevantes), solo el subdominio del IdP.
        sso_host = urlparse(final_url).netloc.split(":")[0]
        result = {
            # Marcador interno (no es una columna): permite mover estas filas
            # a la pestana O365 en lugar de la hoja principal. Se filtra al
            # escribir el Excel, nunca aparece como columna visible.
            "_sso": True,
            "Activo": url,
            "URL final (tras redirecciones)": sso_host,
            "Cabeceras HTTP (X-Powered-By/Server)": omitido,
            "Cookies de sesion": omitido,
            "PHP default": omitido,
            "composer.json/lock expuestos": omitido,
            "WordPress": omitido,
            "Drupal": omitido,
            "Favicon": omitido,
            "CVE-2026-109618 / CVE-2026-109619": omitido,
            "Nmap -sV (servicios/tecnologias + PHP)": omitido,
            "WhatWeb": omitido,
            "Directorios PHP por defecto": omitido,
            "Usa WP": omitido,
            "Usa Drupal": omitido,
            "Usa PHP": omitido,
        }
        if full:
            result["Nikto (PHP findings)"] = omitido
            result["Nuclei technologies"] = omitido
        return result

    # A partir de aqui, TODAS las pruebas se lanzan sobre final_url,
    # que es donde realmente vive la aplicacion tras seguir los 30x.
    host_port = extract_host_port(final_url)

    # Dos optimizaciones/anti-falsos-positivos calculadas UNA vez por activo
    # y reutilizadas en varios check_*, en lugar de repetir la misma peticion:
    #   - home_resp: el GET a la home que necesitan check_headers,
    #     check_cookies, check_wordpress (meta generator) y check_drupal
    #     (cookies/cabeceras). Antes se pedia por separado en cada uno.
    #   - baseline: respuesta a una ruta que seguro no existe, para que las
    #     comprobaciones de rutas por defecto (WordPress, Drupal, directorios
    #     PHP genericos) no confundan un servidor "catch-all" (200/403 para
    #     cualquier ruta) con que esas rutas realmente existen.
    home_resp = safe_request("GET", final_url)
    baseline = get_baseline_response(final_url)

    result = {
        "Activo": url,
        "URL final (tras redirecciones)": final_url,
        "Cabeceras HTTP (X-Powered-By/Server)": check_headers(final_url, home_resp),
        "Cookies de sesion": check_cookies(final_url, home_resp),
        "PHP default": check_php_default(final_url, baseline),
        "composer.json/lock expuestos": check_composer(final_url),
        "WordPress": check_wordpress(final_url, home_resp, baseline),
        "Drupal": check_drupal(final_url, home_resp, baseline),
        "Favicon": check_favicon(final_url),
        "Nmap -sV (servicios/tecnologias + PHP)": run_nmap(host_port),
        "WhatWeb": run_whatweb(final_url),
    }

    # Esta columna se calcula a partir de la version de PHP ya detectada
    # arriba (en varias columnas), sin lanzar ninguna peticion nueva.
    result["CVE-2026-109618 / CVE-2026-109619"] = check_php_cve(result)

    # Analisis de directorios/ficheros genericos propios de instalaciones
    # PHP (vendor/, .env, includes/, etc.), independiente de cualquier CMS.
    result["Directorios PHP por defecto"] = check_php_default_dirs(final_url, baseline)

    # Inteligencia de tecnologias: WP y Drupal se derivan de las columnas
    # ya calculadas arriba ("WordPress" y "Drupal"), sin lanzar peticiones
    # nuevas. Cada derive_*_confidence devuelve tambien su nivel de
    # confianza ("strong"/"weak"/"none"), usado justo despues para
    # reconciliar un posible falso positivo cuando WordPress y Drupal
    # salen "Si" a la vez en el mismo activo por colision de rutas
    # genericas (ver reconcile_cms_detections).
    wp_detectado, wp_confianza = derive_wp_confidence(result.get("WordPress", ""))
    drupal_detectado, drupal_confianza = derive_drupal_confidence(result.get("Drupal", ""))

    result["Usa WP"] = "Si" if wp_detectado else "No"
    result["Usa Drupal"] = "Si" if drupal_detectado else "No"

    reconcile_cms_detections(result, {
        "Usa WP": wp_confianza,
        "Usa Drupal": drupal_confianza,
    })

    # "Usa PHP" se calcula al final, una vez reconciliados WP y Drupal.
    result["Usa PHP"] = flag_php(result)

    if full:
        result["Nikto (PHP findings)"] = run_nikto(final_url)
        result["Nuclei technologies"] = run_nuclei(final_url)

    return result


# --------------------------------------------------------------------------
# Excel
# --------------------------------------------------------------------------
EXCEL_MAX_CELL_CHARS = 32767  # limite duro de Excel por celda
FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell_value(value):
    """
    Deja un valor listo para escribirse en una celda de Excel sin provocar:
      1) IllegalCharacterError de openpyxl (caracteres de control no validos
         en XML, p.ej. bytes nulos o de control que a veces aparecen en
         respuestas HTTP crudas, salidas de nmap/whatweb/nikto, etc.).
      2) Corrupcion/truncado silencioso por exceder el limite de 32767
         caracteres por celda de Excel.
      3) Inyeccion de formulas (CSV/Excel Formula Injection): si el
         contenido viene de una fuente externa no confiable (p.ej. un
         Set-Cookie o un X-Powered-By manipulado por el propio objetivo
         escaneado) y empieza por =, +, - o @, Excel podria interpretarlo
         como una formula al abrir el fichero. Se neutraliza anteponiendo
         un apostrofe, que fuerza texto plano.
    """
    if value is None:
        return ""

    text = str(value)

    # 1) Quitar caracteres de control ilegales para XML/XLSX
    text = ILLEGAL_CHARACTERS_RE.sub("", text)
    # Tambien limpiamos saltos de linea raros que a veces rompen el layout
    text = text.replace("\x00", "")

    # 2) Neutralizar posible inyeccion de formulas
    if text and text[0] in FORMULA_TRIGGER_CHARS:
        text = "'" + text

    # 3) Recortar al limite de Excel, dejando constancia del recorte
    if len(text) > EXCEL_MAX_CELL_CHARS:
        suffix = " ...[TRUNCADO]"
        text = text[: EXCEL_MAX_CELL_CHARS - len(suffix)] + suffix

    return text




def _write_table_to_sheet(ws, columns: list, rows: list) -> int:
    """
    Escribe una tabla (cabecera + filas) en una hoja ya creada, con el
    mismo formato (colores, wrap, sanitizacion) en todas las pestanas del
    documento. Devuelve el numero de celdas que tuvieron que sustituirse
    por caracteres ilegales, para que la llamada pueda acumular el total.
    """
    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")

    for col_idx, col_name in enumerate(columns, start=1):
        cell = ws.cell(row=1, column=col_idx, value=sanitize_cell_value(col_name))
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    skipped_cells = 0
    for row_idx, row_data in enumerate(rows, start=2):
        for col_idx, col_name in enumerate(columns, start=1):
            raw_value = row_data.get(col_name, "")
            safe_value = sanitize_cell_value(raw_value)
            try:
                cell = ws.cell(row=row_idx, column=col_idx, value=safe_value)
            except IllegalCharacterError:
                # Red de seguridad por si, pese a la sanitizacion, algo se cuela:
                # no abortamos el informe entero por una sola celda problematica.
                cell = ws.cell(
                    row=row_idx, column=col_idx,
                    value="[CONTENIDO OMITIDO - caracteres no validos para Excel]",
                )
                skipped_cells += 1
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    widths = {1: 35}
    for col_idx in range(2, len(columns) + 1):
        widths[col_idx] = 45
    for col_idx, width in widths.items():
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    ws.freeze_panes = "A2"
    return skipped_cells


# --------------------------------------------------------------------------
# Pestana Dashboard: tabla de metricas + graficas de tarta nativas de Excel
# (vinculadas a las celdas de la propia tabla, por tanto dinamicas: si
# alguien edita una celda de la tabla a mano, la grafica se actualiza sola).
# --------------------------------------------------------------------------
DASHBOARD_METRICS = [
    # (etiqueta, funcion que decide si una fila "cumple" la metrica)
    (
        "Vulnerables a CVE-2026-109618 / CVE-2026-109619 (PHP)",
        lambda r: str(r.get(CVE_COLUMN_NAME, "")).startswith("VULNERABLE"),
    ),
    ("Usan WordPress", lambda r: r.get("Usa WP") == "Si"),
    ("Usan Drupal", lambda r: r.get("Usa Drupal") == "Si"),
    ("Usan PHP", lambda r: r.get("Usa PHP") == "Si"),
]


def build_dashboard_sheet(wb, normal_rows: list, sso_rows: list):
    ws = wb.create_sheet("Dashboard")

    title_font = Font(bold=True, size=14, color="1F4E78")
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    label_font = Font(bold=True)

    ws["A1"] = "Resumen de activos"
    ws["A1"].font = title_font

    total_general = len(normal_rows) + len(sso_rows)
    resumen = [
        ("Total activos analizados", total_general),
        ("Activos evaluados (sin redireccion a SSO)", len(normal_rows)),
        ("Activos redirigidos a SSO (ver pestana O365)", len(sso_rows)),
    ]
    for i, (etiqueta, valor) in enumerate(resumen, start=2):
        ws.cell(row=i, column=1, value=etiqueta).font = label_font
        ws.cell(row=i, column=2, value=valor)

    # Tabla de metricas: cada fila alimenta directamente a su grafica.
    table_header_row = 6
    headers = ["Metrica", "Cumplen", "No cumplen", "Total evaluados", "% sobre el total"]
    for col_idx, h in enumerate(headers, start=1):
        cell = ws.cell(row=table_header_row, column=col_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    total_evaluados = len(normal_rows)
    first_data_row = table_header_row + 1
    for offset, (label, predicate) in enumerate(DASHBOARD_METRICS):
        row = first_data_row + offset
        cumplen = sum(1 for r in normal_rows if predicate(r))
        no_cumplen = total_evaluados - cumplen
        ws.cell(row=row, column=1, value=label)
        ws.cell(row=row, column=2, value=cumplen)
        ws.cell(row=row, column=3, value=no_cumplen)
        ws.cell(row=row, column=4, value=total_evaluados)
        # Formula nativa de Excel (no un valor fijo), para que el % tambien
        # se recalcule solo si alguien edita la tabla a mano.
        ws.cell(row=row, column=5, value=f"=IF(D{row}=0,0,B{row}/D{row})")
        ws.cell(row=row, column=5).number_format = "0.0%"

    ws.column_dimensions["A"].width = 55
    for col in "BCDE":
        ws.column_dimensions[col].width = 16

    if total_evaluados == 0:
        ws.cell(
            row=first_data_row + len(DASHBOARD_METRICS) + 1, column=1,
            value="Sin activos evaluados (todos redirigieron a SSO): no se generan graficas.",
        )
        return

    # Una grafica de tarta (Cumplen vs No cumplen) por cada metrica,
    # vinculada a su fila de la tabla -> es una grafica nativa de Excel,
    # dinamica, no una imagen estatica.
    #
    # IMPORTANTE: los dos valores (Cumplen, No cumplen) estan en DOS
    # COLUMNAS de UNA MISMA FILA. openpyxl interpreta un Reference por
    # columnas por defecto (from_rows=False): con eso, cada columna se
    # trataria como una SERIE distinta de un solo punto (2 series de 1
    # valor cada una) en vez de UNA serie con 2 valores -> la tarta salia
    # mal formada (series y categorias desalineadas). from_rows=True le
    # dice que lea la fila como una sola serie con sus 2 valores.
    chart_anchor_rows = [table_header_row, table_header_row + 16, table_header_row + 32, table_header_row + 48]
    for offset, (label, _predicate) in enumerate(DASHBOARD_METRICS):
        row = first_data_row + offset
        pie = PieChart()
        pie.title = label
        data = Reference(ws, min_col=2, max_col=3, min_row=row, max_row=row)
        cats = Reference(ws, min_col=2, max_col=3, min_row=table_header_row, max_row=table_header_row)
        pie.add_data(data, titles_from_data=False, from_rows=True)
        pie.set_categories(cats)
        pie.dataLabels = DataLabelList()
        pie.dataLabels.showPercent = True
        pie.height = 7
        pie.width = 11
        anchor = f"G{chart_anchor_rows[offset]}"
        ws.add_chart(pie, anchor)

    # ----------------------------------------------------------------------
    # Desglose adicional especifico del CVE-2026-109618 / CVE-2026-109619:
    # una grafica de barras con 3 categorias (Vulnerables / No vulnerables /
    # Indeterminado) en vez de solo "Cumplen/No cumplen" de la tarta de
    # arriba, para no confundir "confirmado seguro" con "no se pudo
    # determinar la version de PHP" (la tarta de arriba mete ambos casos en
    # el mismo "No cumplen"). Debajo, el listado de los dominios/activos
    # concretos afectados, para identificarlos sin tener que filtrar la
    # hoja principal a mano.
    # ----------------------------------------------------------------------
    vulnerable_rows = [
        r for r in normal_rows
        if str(r.get(CVE_COLUMN_NAME, "")).startswith("VULNERABLE")
    ]
    no_vulnerable_rows = [
        r for r in normal_rows
        if str(r.get(CVE_COLUMN_NAME, "")).startswith("No vulnerable")
    ]
    indeterminado_count = total_evaluados - len(vulnerable_rows) - len(no_vulnerable_rows)

    breakdown_header_row = first_data_row + len(DASHBOARD_METRICS) + 2
    ws.cell(row=breakdown_header_row - 1, column=1,
            value="Desglose CVE-2026-109618 / CVE-2026-109619").font = title_font

    breakdown_headers = ["Estado frente al CVE", "Nº de activos"]
    for col_idx, h in enumerate(breakdown_headers, start=1):
        cell = ws.cell(row=breakdown_header_row, column=col_idx, value=h)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    breakdown_data = [
        ("Vulnerables", len(vulnerable_rows)),
        ("No vulnerables (version segura)", len(no_vulnerable_rows)),
        ("Indeterminado (sin version de PHP detectada)", indeterminado_count),
    ]
    breakdown_first_row = breakdown_header_row + 1
    for offset, (etiqueta, valor) in enumerate(breakdown_data):
        row = breakdown_first_row + offset
        ws.cell(row=row, column=1, value=etiqueta)
        ws.cell(row=row, column=2, value=valor)
    breakdown_last_row = breakdown_first_row + len(breakdown_data) - 1

    # Grafica de barras (no de tarta, para distinguirla visualmente de las
    # de arriba) con las 3 categorias del desglose. Misma logica de
    # from_rows/from_cols que las tartas: aqui los datos van en COLUMNA
    # (B{primera}:B{ultima}), que es justo el caso por defecto de
    # add_data (from_rows=False), asi que no hace falta tocarlo.
    bar = BarChart()
    bar.type = "col"
    bar.title = "Activos frente al CVE (desglose)"
    bar.y_axis.title = "Nº de activos"
    bar_data = Reference(ws, min_col=2, min_row=breakdown_header_row, max_row=breakdown_last_row)
    bar_cats = Reference(ws, min_col=1, min_row=breakdown_first_row, max_row=breakdown_last_row)
    bar.add_data(bar_data, titles_from_data=True)
    bar.set_categories(bar_cats)
    bar.legend = None
    bar.height = 7
    bar.width = 11
    bar_anchor_row = chart_anchor_rows[-1] + 16
    ws.add_chart(bar, f"G{bar_anchor_row}")

    # Listado de los activos vulnerables concretos (dominio + detalle).
    domains_header_row = breakdown_last_row + 3
    ws.cell(row=domains_header_row - 1, column=1,
            value="Activos vulnerables a CVE-2026-109618 / CVE-2026-109619").font = title_font

    if not vulnerable_rows:
        ws.cell(row=domains_header_row, column=1,
                value="Ningun activo vulnerable detectado.")
    else:
        domains_headers = ["Activo", "URL final (tras redirecciones)", "Detalle"]
        for col_idx, h in enumerate(domains_headers, start=1):
            cell = ws.cell(row=domains_header_row, column=col_idx, value=h)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        for offset, r in enumerate(vulnerable_rows):
            row = domains_header_row + 1 + offset
            ws.cell(row=row, column=1, value=sanitize_cell_value(r.get("Activo", "")))
            ws.cell(row=row, column=2, value=sanitize_cell_value(r.get("URL final (tras redirecciones)", "")))
            ws.cell(row=row, column=3, value=sanitize_cell_value(r.get(CVE_COLUMN_NAME, "")))
            ws.cell(row=row, column=3).alignment = Alignment(vertical="top", wrap_text=True)


def write_excel(results: list, output_path: str):
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    # Las filas marcadas con _sso (redirigidas a un IdP corporativo, p.ej.
    # login.microsoftonline.com) se MUEVEN a la pestana O365: no se
    # evaluaron, asi que no aportan nada util a la hoja principal, a la
    # pestana CMS ni al Dashboard.
    normal_rows = [r for r in results if not r.get("_sso")]
    sso_rows = [r for r in results if r.get("_sso")]

    # Columnas visibles: igual para las tres pestanas de detalle (principal
    # y O365), excluyendo el marcador interno "_sso".
    sample_row = normal_rows[0] if normal_rows else (sso_rows[0] if sso_rows else {"Activo": ""})
    columns = [k for k in sample_row.keys() if not k.startswith("_")]

    wb = Workbook()
    ws_main = wb.active
    ws_main.title = "PHP Version Recon"
    skipped_cells = _write_table_to_sheet(ws_main, columns, normal_rows)

    # Pestana "O365": activos cuya redireccion llevo a un login corporativo
    # (Microsoft 365 / Entra ID). Mismas columnas que la hoja principal,
    # para que quede claro que fila a fila es el mismo formato, solo que
    # todo salvo Activo/URL final quedo sin evaluar ("-").
    ws_o365 = wb.create_sheet("O365")
    skipped_cells += _write_table_to_sheet(ws_o365, columns, sso_rows)
    if not sso_rows:
        ws_o365.cell(row=2, column=1, value="Ningun activo redirigio a un login corporativo (SSO).")

    # Pestana "Dashboard": metricas + graficas nativas, calculadas solo
    # sobre los activos evaluados (normal_rows).
    build_dashboard_sheet(wb, normal_rows, sso_rows)

    if skipped_cells:
        print(
            f"[!] {skipped_cells} celda(s) tenian caracteres no validos y se "
            f"sustituyeron por un aviso para no romper el Excel.",
            file=sys.stderr,
        )

    wb.save(output_path)

    if not os.path.isfile(output_path):
        print(f"[!] ERROR: el fichero {output_path} no se creo correctamente.", file=sys.stderr)
        sys.exit(1)

    size_kb = os.path.getsize(output_path) / 1024
    print(
        f"[+] Excel generado correctamente: {output_path} "
        f"({len(normal_rows)} filas evaluadas x {len(columns)} columnas en 'PHP Version Recon'; "
        f"{len(sso_rows)} activo(s) movidos a 'O365'; pestana 'Dashboard' generada; "
        f"{size_kb:.1f} KB)",
        file=sys.stderr,
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Recon de version de PHP sobre una lista de activos (uso autorizado)."
    )
    parser.add_argument("-i", "--input", required=True, help="Fichero con un activo por linea")
    parser.add_argument("-o", "--output", default="php_version_recon.xlsx", help="Fichero Excel de salida")
    parser.add_argument("--full", action="store_true", help="Incluye nikto y nuclei (mas lento)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Hilos en paralelo (default 5)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not targets:
        print("[!] No se encontraron activos en el fichero de entrada.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] {len(targets)} activos cargados. Lanzando escaneo con {args.threads} hilos...", file=sys.stderr)

    # Normalizamos los activos igual que hace scan_target (anade http:// si falta)
    # para poder reordenar los resultados exactamente como en el fichero de entrada,
    # incluso cuando llegan desordenados desde el ThreadPoolExecutor.
    normalized_targets = [
        t if t.startswith("http") else "http://" + t
        for t in targets
    ]
    order = {url: i for i, url in enumerate(normalized_targets)}

    results = []
    failed = []
    total = len(targets)
    completed = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_target, t, args.full): t for t in targets}
        for future in as_completed(futures):
            original_target = futures[future]
            try:
                res = future.result()
            except Exception as e:
                log(f"[!] Error inesperado escaneando {original_target}: {e}")
                res = None

            completed += 1
            percent = (completed / total) * 100

            if res:
                results.append(res)
            else:
                failed.append(original_target)

            # Progreso SOLO por terminal (stderr): nunca se escribe en el Excel,
            # el diccionario `res` que va al Excel no se toca aqui para nada.
            log(
                f"[progreso] {completed}/{total} activos procesados ({percent:5.1f}%) "
                f"- ultimo: {original_target}"
            )

    results.sort(key=lambda r: order.get(r["Activo"], len(order)))

    if failed:
        print(f"[!] {len(failed)} activo(s) no pudieron procesarse: {failed}", file=sys.stderr)

    if not results:
        print("[!] No se obtuvo ningun resultado valido. No se genera el Excel.", file=sys.stderr)
        sys.exit(1)

    write_excel(results, args.output)


if __name__ == "__main__":
    main()
