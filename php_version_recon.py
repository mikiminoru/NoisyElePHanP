#!/usr/bin/env python3
"""
php_version_recon.py
---------------------
Reconnaissance script to identify the PHP version used by a list of web
applications, intended ONLY for use in pentests or bug bounty programs
with explicit authorization over the assets.

Reads a text file with one asset (URL) per line, runs several
fingerprinting techniques against each one, and dumps the results into
an Excel workbook and an equivalent HTML report: one row per asset, one
column per technique/tool. Output files are named automatically as
"output_<date>_<time>.xlsx"/".html" (timestamp of the moment the scan
finishes), so that each run leaves its own files without overwriting
those of a previous run.

Requirements:
    pip install requests openpyxl

Optional external tools (used if they are installed in the PATH;
otherwise that column is filled with "N/A - tool not found"):
    - nmap        (http-php-version script)
    - whatweb
    - nikto
    - nuclei
    - ffuf

Usage:
    python3 php_version_recon.py -i assets.txt
    python3 php_version_recon.py -i assets.txt --full
        (--full enables nikto and nuclei, slower)

Input file format (one asset per line):
    https://example1.com
    https://example2.com
    http://192.168.1.10:8080
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
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

# Limit of CONCURRENT requests WITHIN a single asset (not to be confused
# with --threads, which parallelizes BETWEEN different assets). The dozens
# of default paths that each technique checks (WordPress, Drupal, generic
# PHP...) are independent from one another, so they are launched in small
# parallel batches to reduce the scan time per asset, without firing an
# uncontrolled burst of simultaneous requests against the same host
# (relevant in a pentest: less noise, lower risk of triggering a target's
# WAF/rate-limit).
PER_ASSET_CONCURRENCY = 6

PHPINFO_PATHS = [
    "phpinfo.php", "info.php", "test.php", "i.php",
    "php_info.php", "_phpinfo.php", "pinfo.php",
]

# PHP error log files that sometimes end up exposed at the root of the
# document root when log_errors=On and error_log isn't relocated outside
# it (default path of many misconfigured PHP/Apache installations).
PHP_ERROR_LOG_PATHS = [
    "error_log", "php_errorlog", "error.log",
    "php-error.log", "logs/error_log", "logs/php_errorlog",
]
# Typical strings of a real PHP error log, to avoid a false positive with
# "catch-all" pages that return 200 for any path.
PHP_ERROR_LOG_MARKERS = (
    "php warning", "php fatal error", "php notice",
    "php deprecated", "php parse error", "stack trace:",
)
COMPOSER_PATHS = ["composer.json", "composer.lock"]

# Generic README files (several extensions/name variants), not tied to
# any specific CMS: a lot of PHP software (frameworks, libraries, admin
# panels...) documents here the minimum PHP version required, valuable
# information that used to be lost if the file wasn't exactly
# WordPress's readme.html.
README_PATHS = [
    "readme.html",
    "readme.txt",
    "README.txt",
    "readme.md",
    "README.md",
    "README",
    "readme",
]

# WordPress default paths, split into DIRECTORIES and FILES (so they can
# be shown in different columns on the "WP" tab). Their mere presence
# (200/301/302/403, i.e. "not 404") is already an indication that the app
# runs on WordPress.
WORDPRESS_DIRS = [
    "wp-admin/",
    "wp-content/",
    "wp-content/themes/",
    "wp-content/plugins/",
    "wp-content/uploads/",
    "wp-includes/",
    "wp-includes/js/",
    "wp-json/",
    "feed/",
]
WORDPRESS_FILES = [
    "wp-login.php",
    "wp-admin/admin-ajax.php",
    "wp-admin/install.php",
    "wp-includes/version.php",
    "wp-config.php",
    "wp-config-sample.php",
    "wp-cron.php",
    "wp-settings.php",
    "wp-load.php",
    "wp-blog-header.php",
    "xmlrpc.php",
    "readme.html",
    "license.txt",
]

# Drupal default paths (classic D7 and D8+ with the core/ prefix), split
# into DIRECTORIES/FILES (for the "Drupal" tab) and, within each, into
# STRONG (practically exclusive to Drupal) and WEAK (generic, also
# appear in apps that are not Drupal - a single hit here is not enough,
# >= 2 are required to consider them evidence).
DRUPAL_STRONG_DIRS = [
    "sites/default/files/",
    "sites/all/modules/",
    "core/modules/",
]
DRUPAL_STRONG_FILES = [
    "core/misc/drupal.js",
    "misc/drupal.js",
    "sites/default/settings.php",
    "sites/default/default.settings.php",
    "core/MAINTAINERS.txt",
    "core/authorize.php",
]
DRUPAL_WEAK_DIRS = [
    "modules/",   # generic (D7 without the sites/all/ prefix), a lot of software uses it
]
DRUPAL_WEAK_FILES = [
    "core/CHANGELOG.txt",
    "CHANGELOG.txt",     # a lot of non-Drupal software also exposes it
    "core/INSTALL.txt",
    "INSTALL.txt",
    "core/LICENSE.txt",
    "user/login",        # generic login path, not exclusive to Drupal
    "user/register",
    "user/password",
    "core/install.php",
    "install.php",
    "core/update.php",
    "update.php",
    "cron.php",
    "node/1",
]

# Generic directories/files typical of PHP installations, not tied to
# any specific CMS. A finding here does not by itself imply a CMS, but
# it does contribute evidence (variable depending on the path) that the
# app runs PHP.
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

# Subset of PHP_GENERIC_PATHS that is STRONG, PHP-specific evidence (not
# generic to any web stack), also used by has_direct_php_evidence to
# compute "Uses PHP".
PHP_GENERIC_STRONG_SIGNALS = {"vendor/", "vendor/autoload.php", ".env"}

# --------------------------------------------------------------------------
# Favicon hashing ("Favicon" column)
# MD5 of the RAW content of favicon.ico, compared against default hashes
# of un-customized installations. Hash source: OWASP Favicon Database
# (https://community.owasp.org/favicons_database). MD5 over the raw bytes
# is used (not Shodan's mmh3/base64) because those are the verifiable
# values from that source; a hash that doesn't match is not evidence of
# anything (a custom favicon), only a match is a signal.
# --------------------------------------------------------------------------
FAVICON_MD5_HASHES = {
    # WordPress (several versions and default themes)
    "fa54dbf2f61bd2e0188e47f5f578f736": "WordPress",
    "6cec5a9c106d45e458fc680f70df91b0": "WordPress (outdated version)",
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
    # Other PHP applications/CMS with a recognizable default favicon
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

# Usual paths where the favicon is published
FAVICON_PATHS = ["favicon.ico"]

HEADERS_UA = {"User-Agent": "Mozilla/5.0 (PHP-Recon-Scan; authorized-pentest)"}

# --------------------------------------------------------------------------
# CVE-2026-109618 / CVE-2026-109619 (PHP web runtimes)
# Source: https://aws.amazon.com/security/security-bulletins/2026-143-aws/
# Key = (major, minor) of the PHP branch; value = (patch of the first
# fixed version, text of that version). Branches 5.4-8.1 are EOL and have
# no patch available according to the bulletin.
# --------------------------------------------------------------------------
AWS_BULLETIN_URL = "https://aws.amazon.com/security/security-bulletins/2026-143-aws/"
CVE_COLUMN_NAME = "CVE-2026-109618 / CVE-2026-109619"
PHP_CVE_FIXED_VERSIONS = {
    (8, 5): (12, "8.5.12"),
    (8, 4): (27, "8.4.27"),
    (8, 3): (36, "8.3.36"),
    (8, 2): (35, "8.2.35"),
}
PHP_EOL_NO_FIX_RANGE = ((5, 4), (8, 1))  # inclusive: 5.4 through 8.1



# Lock used ONLY so that prints from different threads (the "[*] Scanning
# ..." messages and the progress bar) don't get mixed up with one another
# in the terminal. It has no relation whatsoever with the data that ends
# up in the Excel file.
_print_lock = threading.Lock()


def log(msg: str):
    """Prints to stderr atomically across threads. Terminal output only."""
    with _print_lock:
        print(msg, file=sys.stderr)


# --------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------
def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_request(method, url, session=None, **kwargs):
    """
    Wrapper around requests.request with a fixed timeout/verify/headers
    for the whole script. If `session` is passed (a requests.Session
    created once per asset in scan_target), the request is made through
    it to reuse the TCP/TLS connection (keep-alive) with the same host
    instead of opening a new connection for each of the dozens of
    requests launched against a single asset. Without `session` (e.g. in
    the tests, which replace this function with a fake one) it behaves
    exactly as before.
    """
    kwargs.setdefault("allow_redirects", True)
    requester = session.request if session is not None else requests.request
    try:
        return requester(
            method, url, timeout=TIMEOUT, verify=False,
            headers=HEADERS_UA, **kwargs
        )
    except requests.RequestException:
        return None


class ScanContext:
    """
    Groups the shared state while scanning ONE asset, so that the
    check_* functions don't have to be passed session/cache/concurrency
    separately:

      - `session`: requests.Session reused across all requests for this
        asset (keep-alive).
      - `cache`: dict {path: response}. Several different columns/
        techniques sometimes check the SAME default path (e.g.
        "readme.html" is used both by "Default PHP paths" and WordPress
        detection, and "wp-includes/version.php"/"CHANGELOG.txt" are
        requested both to check existence and to extract the version):
        with the cache, each path is requested at most once per asset
        instead of 2-3 times.
      - `max_workers`: number of concurrent requests allowed when
        checking a list of default paths WITHIN this asset
        (customizable by the user via --path-threads). Not to be
        confused with --threads, which parallelizes BETWEEN different
        assets.

    If a check_* function is called without ctx (e.g. from the tests,
    which call the standalone functions directly), a new "disposable"
    one is created (no session -> each request uses plain
    requests.request; empty cache) so that the behavior is identical to
    before this class was introduced.
    """

    def __init__(self, session=None, max_workers=None):
        self.session = session
        self.cache = {}
        self.max_workers = max_workers if max_workers else PER_ASSET_CONCURRENCY

    @staticmethod
    def ensure(ctx):
        return ctx if ctx is not None else ScanContext()


REDIRECT_CODES = (301, 302, 303, 304, 307, 308)

# Corporate SSO/IdP domains against which it makes no sense (nor is it
# ethical) to run fingerprinting: if the app redirects here, the real
# asset is behind federated authentication and the finding is flagged
# without continuing to test.
SSO_DOMAINS = (
    "login.microsoftonline.com",
)


def is_sso_redirect(url: str) -> bool:
    """
    Compares by exact domain or real subdomain (host == sso or
    host.endswith('.' + sso)), never by substring, to avoid false
    positives/negatives with typosquatting domains like
    'login.microsoftonline.com.evil.com' or 'evil-login.microsoftonline.com.com'.
    """
    try:
        host = urlparse(url).netloc.lower().split(":")[0]  # strip the port if present
    except Exception:
        return False
    return any(host == sso or host.endswith("." + sso) for sso in SSO_DOMAINS)


def resolve_redirect_chain(url: str, max_redirects: int = 10, ctx: "ScanContext" = None):
    """
    Manually follows the redirects (301/302/303/304/307/308) starting
    from `url`, returning the final URL against which the rest of the
    tests should be run, and the full chain of hops to keep it
    documented. This is done by hand (allow_redirects=False) instead of
    delegating to requests, in order to be able to log each hop and
    detect loops.
    """
    ctx = ScanContext.ensure(ctx)
    chain = [url]
    current = url
    visited = {url}

    for _ in range(max_redirects):
        resp = safe_request("GET", current, session=ctx.session, allow_redirects=False)
        if resp is None:
            break

        if resp.status_code not in REDIRECT_CODES:
            break

        location = resp.headers.get("Location")
        if not location:
            # e.g. 304 Not Modified with no Location: nowhere to jump to
            break

        next_url = urljoin(current, location)
        if next_url in visited:
            chain.append(f"{next_url} (loop detected, stopping here)")
            break

        chain.append(next_url)
        visited.add(next_url)
        current = next_url

        if is_sso_redirect(current):
            # We don't follow any more hops or launch extra requests against the IdP.
            break

    return current, chain


# --------------------------------------------------------------------------
# "Soft 404" / catch-all detection (anti false positives)
# --------------------------------------------------------------------------
# Many of the check_* functions check default paths by only looking at
# the status code (200/301/302/403 = "exists"). This fails with servers
# that return 200/403 for ANY path (an SPA that always serves index.html,
# a WAF that responds the same to everything, a custom error page with
# 200...): in that case ALL the paths of ALL the CMSs would "exist" at
# the same time, giving cascading false positives. get_baseline_response()
# requests a path that is practically guaranteed not to exist, once per
# asset, and path_looks_real() discards as catch-all any hit whose status
# and content length match that baseline.
def get_baseline_response(base_url: str, ctx: "ScanContext" = None):
    """
    Requests a random path that shouldn't exist in any real installation,
    to use as a reference "generic response" (catch-all) from the server.
    It is computed once per asset and reused in all the check_* functions
    that iterate over lists of default paths.
    """
    ctx = ScanContext.ensure(ctx)
    nonce = f"__recon_baseline_{os.urandom(6).hex()}__/does-not-exist.xyz"
    url = urljoin(base_url.rstrip("/") + "/", nonce)
    resp = safe_request("GET", url, session=ctx.session)
    if resp is None:
        return None
    return {"status": resp.status_code, "length": len(resp.content or b"")}


def path_looks_real(resp, baseline) -> bool:
    """
    True if the response to a default path looks like a real hit and not
    a catch-all: either there is no baseline available (it couldn't be
    computed, we fall back to the previous behavior), or the status/
    length doesn't match the server's generic response for non-existent
    paths. A 5-byte tolerance on the length so as not to fail because of
    counters or variable timestamps on dynamic error pages.
    """
    if baseline is None:
        return True
    if resp.status_code != baseline["status"]:
        return True
    length = len(resp.content or b"")
    return abs(length - baseline["length"]) > 5


def fetch_path(base_url: str, path: str, ctx: "ScanContext"):
    """
    Returns the GET response to `path` relative to `base_url`, cached per
    asset in ctx.cache: if that same path has already been requested
    before (from any check_*, even a different one), the in-memory
    response is reused instead of repeating the network request. This is
    what prevents, e.g., "readme.html" from being requested separately
    from "Default PHP paths" and from WordPress detection, or
    "wp-includes/version.php"/"CHANGELOG.txt" from being requested twice
    (once to check existence and again to extract the version).
    """
    if path in ctx.cache:
        return ctx.cache[path]
    url = urljoin(base_url.rstrip("/") + "/", path)
    resp = safe_request("GET", url, session=ctx.session)
    ctx.cache[path] = resp
    return resp


def fetch_paths_parallel(base_url: str, paths: list, ctx: "ScanContext") -> dict:
    """
    Requests all the paths in `paths` that aren't yet in ctx.cache, up to
    ctx.max_workers at a time (parallelism WITHIN this asset, limited so
    as not to fire an uncontrolled burst of simultaneous requests against
    the same host), and returns a dict {path: response} with ALL the
    requested paths (both the ones just requested and the ones already in
    cache).
    """
    # dict.fromkeys preserves order and removes duplicates within the
    # list itself, in case a path appears twice in `paths`.
    pending = [p for p in dict.fromkeys(paths) if p not in ctx.cache]
    if len(pending) == 1:
        # Trivial case (e.g. check_favicon, which only checks one path):
        # it doesn't make sense to set up a ThreadPoolExecutor for a
        # single request, so it is requested directly without the
        # overhead of creating the thread pool.
        fetch_path(base_url, pending[0], ctx)
    elif pending:
        workers = max(1, min(ctx.max_workers, len(pending)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(fetch_path, base_url, p, ctx) for p in pending]
            for future in as_completed(futures):
                future.result()  # fetch_path already writes the result into ctx.cache
    return {p: ctx.cache.get(p) for p in paths}


def find_existing_paths(base_url: str, paths: list, baseline=None, ctx: "ScanContext" = None) -> list:
    """
    Shared helper: checks all the `paths` (in parallel, see
    fetch_paths_parallel) and considers "existing" any whose status is
    200/301/302/403 AND (if there is a baseline) doesn't look like a
    generic catch-all. Centralizes logic that used to be duplicated
    almost identically in check_wordpress, check_drupal and
    check_php_default_dirs.
    """
    ctx = ScanContext.ensure(ctx)
    responses = fetch_paths_parallel(base_url, paths, ctx)
    found = []
    for path in paths:
        resp = responses.get(path)
        if resp is None or resp.status_code not in (200, 301, 302, 403):
            continue
        if not path_looks_real(resp, baseline):
            continue
        found.append(path)
    return found


# --------------------------------------------------------------------------
# Individual techniques
# --------------------------------------------------------------------------
def check_headers(base_url: str, home_resp=None, ctx: "ScanContext" = None) -> str:
    """X-Powered-By / Server headers"""
    ctx = ScanContext.ensure(ctx)
    resp = home_resp if home_resp is not None else safe_request("GET", base_url, session=ctx.session)
    if resp is None:
        return "ERROR - no response"
    xpb = resp.headers.get("X-Powered-By", "")
    server = resp.headers.get("Server", "")
    parts = []
    if xpb:
        parts.append(f"X-Powered-By: {xpb}")
    if server:
        parts.append(f"Server: {server}")
    return " | ".join(parts) if parts else "Not exposed"


def check_cookies(base_url: str, home_resp=None, ctx: "ScanContext" = None) -> str:
    """Name and shape of the session cookies"""
    ctx = ScanContext.ensure(ctx)
    resp = home_resp if home_resp is not None else safe_request("GET", base_url, session=ctx.session)
    if resp is None:
        return "ERROR - no response"
    set_cookie = resp.headers.get("Set-Cookie", "")
    cookies_found = []
    for c in resp.cookies:
        cookies_found.append(f"{c.name}={c.value[:12]}...")
    if not cookies_found and set_cookie:
        cookies_found.append(set_cookie[:80])
    return " | ".join(cookies_found) if cookies_found else "No cookies in initial response"


def check_php_default(base_url: str, baseline=None, ctx: "ScanContext" = None) -> str:
    """
    "Default PHP paths" column: checks paths and files that only appear
    on default or misconfigured PHP installations:
      1) phpinfo() exposed at the usual paths (phpinfo.php, info.php...).
      2) PHP error log exposed at the root (error_log, php_errorlog...),
         when log_errors=On and error_log wasn't relocated outside the
         document root - critical information disclosure in addition to
         a PHP signal.
      3) README files (several extensions: .html/.txt/.md/no extension),
         identifying the accessible file and, if it states it, the
         minimum PHP version required by the application - useful
         whether it's WordPress or any other PHP software.

    Each finding is ONE line within the same cell (separated by a line
    break, not by " | "), so as not to compress the information of
    several different files into a single sentence when there is more
    than one.

    `baseline` (from get_baseline_response) is used in the README block
    so as not to mistake a "catch-all" server (200 for any path) for
    several different READMEs actually existing.

    The three lists of paths (phpinfo/error_log/README) are requested in
    a single parallel batch (see fetch_paths_parallel) instead of one
    after another; some of these paths (e.g. "readme.html") may already
    be in ctx.cache if another technique (WordPress) requested it
    before, avoiding a repeated request.
    """
    ctx = ScanContext.ensure(ctx)
    findings = []

    all_paths = PHPINFO_PATHS + PHP_ERROR_LOG_PATHS + README_PATHS
    responses = fetch_paths_parallel(base_url, all_paths, ctx)

    for path in PHPINFO_PATHS:
        resp = responses.get(path)
        if resp is not None and resp.status_code == 200 and "phpinfo" in resp.text.lower():
            match = re.search(r"PHP Version\s*</td>\s*<td[^>]*>\s*(\d+(?:\.\d+)*)", resp.text, re.IGNORECASE)
            version = match.group(1) if match else "version not parsed"
            findings.append(f"{path} -> EXPOSED ({version})")

    for path in PHP_ERROR_LOG_PATHS:
        resp = responses.get(path)
        if resp is not None and resp.status_code == 200 and len(resp.text.strip()) > 0:
            body = resp.text.lower()
            if any(marker in body for marker in PHP_ERROR_LOG_MARKERS):
                # PHP-specific marker in the content: strong evidence,
                # always shown even if it matches the baseline (a generic
                # catch-all isn't going to contain "PHP Fatal error" by
                # chance).
                findings.append(f"{path} -> EXPOSED (PHP error log confirmed)")
            elif path_looks_real(resp, baseline):
                # Responds 200 with content but without the typical
                # markers: we still note it, without claiming it's a
                # real log, but only if it doesn't look like the
                # server's generic catch-all response (otherwise it
                # would be 6 identical lines of noise for each asset
                # with that kind of server).
                findings.append(f"{path} -> accessible (not confirmed as a PHP log)")

    for path in README_PATHS:
        resp = responses.get(path)
        if resp is None or resp.status_code != 200 or not resp.text.strip():
            continue
        if not path_looks_real(resp, baseline):
            continue
        min_php = extract_min_php_from_generic_readme(resp.text)
        if min_php:
            findings.append(f"{path} -> accessible | minimum PHP required: {min_php}")
        else:
            findings.append(f"{path} -> accessible (no minimum PHP version detected)")

    return "\n".join(findings) if findings else "None exposed"


def check_composer(base_url: str, ctx: "ScanContext" = None) -> str:
    """Tests whether composer.json / composer.lock are exposed"""
    ctx = ScanContext.ensure(ctx)
    findings = []
    responses = fetch_paths_parallel(base_url, COMPOSER_PATHS, ctx)
    for path in COMPOSER_PATHS:
        resp = responses.get(path)
        if resp is not None and resp.status_code == 200 and len(resp.text) > 20:
            php_req = re.search(r'"php"\s*:\s*"([^"]+)"', resp.text)
            extra = f" (php requirement: {php_req.group(1)})" if php_req else ""
            findings.append(f"{path} -> EXPOSED{extra}")
    return " | ".join(findings) if findings else "Not exposed"


# --------------------------------------------------------------------------
# CVE-2026-109618 / CVE-2026-109619 (PHP) - local logic, no network, based
# on the AWS bulletin. Requires no additional request: it reuses what was
# already detected in the Excel's own columns.
# --------------------------------------------------------------------------
def parse_version_tuple(version_str: str):
    """'7.4.3' -> (7, 4, 3). '8.1' -> (8, 1, 0). None if there's no match."""
    if not version_str:
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not m:
        return None
    major, minor, patch = m.groups()
    return (int(major), int(minor), int(patch) if patch else 0)


def extract_php_version_from_result(result: dict):
    """
    Looks for a PHP version already detected in the result's own columns,
    in order of reliability (from most to least direct), and returns
    (version, source) or (None, None) if none was found.
    """
    # 1) phpinfo exposed: "phpinfo.php -> EXPOSED (7.4.3)"
    phpinfo_col = result.get("Default PHP paths", "") or ""
    m = re.search(r"EXPOSED\s*\(([\d]+\.[\d]+(?:\.[\d]+)?)\)", phpinfo_col)
    if m:
        return m.group(1), "exposed phpinfo"

    # 2) X-Powered-By header: PHP/7.4.3
    headers_col = result.get("HTTP Headers (X-Powered-By/Server)", "") or ""
    m = re.search(r"PHP/([\d]+\.[\d]+(?:\.[\d]+)?)", headers_col, re.IGNORECASE)
    if m:
        return m.group(1), "X-Powered-By header"

    # 3) nmap output (http-php-version script -> "Version: 7.4.3", or
    #    service banner with "PHP/7.4.3")
    nmap_col = result.get("Nmap -sV (services/technologies + PHP)", "") or ""
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
    Compares the detected PHP version (if any) against the AWS bulletin
    for CVE-2026-109618 / CVE-2026-109619.
    """
    version_str, source = extract_php_version_from_result(result)
    if not version_str:
        return "Could not determine the PHP version to check it against the bulletin"

    version = parse_version_tuple(version_str)
    if version is None:
        return f"Could not parse the detected version ({version_str})"

    major, minor, patch = version
    branch = (major, minor)

    if branch in PHP_CVE_FIXED_VERSIONS:
        fix_patch, fix_label = PHP_CVE_FIXED_VERSIONS[branch]
        if patch < fix_patch:
            return (
                f"VULNERABLE - CVE-2026-109618 / CVE-2026-109619 "
                f"(detected {version_str} via {source}; fixed in {fix_label})"
            )
        return f"Not vulnerable - {version_str} >= {fix_label} (via {source})"

    eol_start, eol_end = PHP_EOL_NO_FIX_RANGE
    if eol_start <= (major, minor) <= eol_end:
        return (
            f"VULNERABLE (EOL branch {eol_start[0]}.{eol_start[1]}-{eol_end[0]}.{eol_end[1]}, "
            f"no patch available) - CVE-2026-109619 (interim mitigation) / "
            f"CVE-2026-109618 (no fix) - detected {version_str} via {source}"
        )

    if (major, minor) > max(PHP_CVE_FIXED_VERSIONS.keys()):
        return f"Version {version_str} not covered by AWS bulletin 2026-143 (later, verify manually)"

    return f"Version {version_str} earlier than the range covered by AWS bulletin 2026-143 (verify manually)"


def _strip_html_tags(html_text: str) -> str:
    """
    Removes HTML tags and collapses whitespace/line breaks into a single
    space, leaving plain text ready for a regex search that doesn't need
    to worry about the searched-for version being split by a tag in the
    middle (e.g. "PHP</a> version <strong>7.4"). Shared by
    extract_min_php_from_readme and extract_min_php_from_generic_readme,
    which used to each repeat this same pair of re.sub() calls on their
    own.
    """
    plain = re.sub(r"<[^>]+>", " ", html_text)
    return re.sub(r"\s+", " ", plain)


def extract_min_php_from_readme(readme_text: str):
    """
    WordPress core's real readme.html expresses the PHP requirement as
    HTML, typically:
      <li><a href="https://www.php.net/">PHP</a> version <strong>7.4</strong> or greater.</li>
    (sometimes there are two <li> of this kind: minimum requirement and
    recommended version; we keep the first one, which is the minimum).
    It is first tried against that exact HTML pattern and, if it doesn't
    appear (older or slightly different installations), it falls back to
    a search over the text with the tags already stripped.
    """
    # 1) HTML pattern as generated by WordPress itself
    m = re.search(
        r"PHP</a>\s*version\s*<strong>(\d+(?:\.\d+)*)</strong>",
        readme_text, re.IGNORECASE,
    )
    if m:
        return m.group(1)

    # 2) Fallback: strip HTML tags and search in plain text
    plain = _strip_html_tags(readme_text)
    m = re.search(
        r"PHP\s+version\s+(\d+(?:\.\d+)*)\s+or\s+(?:greater|higher)",
        plain, re.IGNORECASE,
    )
    return m.group(1) if m else None


def extract_min_php_from_generic_readme(readme_text: str):
    """
    Looks for the minimum required PHP version in a generic README of
    ANY PHP application (not just WordPress), trying several common ways
    of expressing it, from most to least specific:
      - WordPress's own HTML pattern (reuses extract_min_php_from_readme,
        in case the README isn't from WP but uses a similar format).
      - WP plugin/theme readme.txt header: "Requires PHP: 7.4".
      - "Requires PHP >= 7.4" / "requires php 7.4 or higher".
      - "PHP >= 7.4" / "PHP: >=7.4" (badges and requirement tables).
      - "PHP minimum: 7.4" / "PHP minimum version: 7.4".
    The word "php" is always required right next to the version number so
    as not to mistakenly extract the software's own version (which also
    tends to appear in a README) instead of PHP's.
    """
    m_wp = extract_min_php_from_readme(readme_text)
    if m_wp:
        return m_wp

    plain = _strip_html_tags(readme_text)

    patterns = [
        r"Requires\s+PHP\s*:?\s*>?=?\s*(\d+(?:\.\d+)*)",
        r"PHP\s*(?:minimo|minimum)(?:\s+version)?\s*:?\s*(\d+(?:\.\d+)*)",
        r"PHP\s*:?\s*>=\s*(\d+(?:\.\d+)*)",
        r"PHP\s+(\d+(?:\.\d+)*)\s+or\s+(?:greater|higher|later|newer)",
        r"requires?\s+php\s+(\d+(?:\.\d+)*)",
    ]
    for pattern in patterns:
        m = re.search(pattern, plain, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def check_wordpress_detailed(base_url: str, home_resp=None, baseline=None, ctx: "ScanContext" = None) -> dict:
    """
    Checks for WordPress usage and returns EVERYTHING identified
    separately, so that the information (what was found) and the
    methodology (how it was found) remain traceable in different columns
    instead of being mixed into a single sentence:

      "dirs_found":        list of accessible default directories.
      "files_found":       list of accessible default files.
      "version_entries":   list of "file -> identified data" lines
                            (WordPress version and/or minimum required
                            PHP version, each with the exact file it came
                            from).
      "version":           the WordPress version (the first one that
                            could be extracted, in order of reliability),
                            or None if none was identified.
      "detected":          True if there is any indication (directory,
                            file or version data).
      "confidence":        "strong" if a specific version was identified
                            (via readme.html/version.php/meta generator/
                            feed, all WordPress-specific); "weak" if only
                            default directories/files were found without
                            being able to confirm the version; "none" if
                            there is nothing.

    Version/minimum-PHP sources, in order:
      1) readme.html             -> "Version X.X" + minimum required PHP
      2) wp-includes/version.php -> $wp_version = 'X.X' (and also
         $required_php_version = 'X.X') - only gives something if the
         server is misconfigured and serves the .php file as plain text.
      3) <meta name="generator"> on the home page (WordPress version only).
      4) generator tag of the /feed/ RSS feed (same).

    `baseline` (from get_baseline_response) discards paths that are
    actually a generic catch-all from the server; `home_resp` avoids
    repeating the GET to the home page already done by
    check_headers/check_cookies.

    "readme.html" and "wp-includes/version.php" are also in
    WORDPRESS_FILES (requested for the existence check that feeds
    "files_found"); here that same response is reused via ctx.cache
    (fetch_path) instead of downloading them again to extract the
    version, eliminating what used to be 2 duplicate requests.
    """
    ctx = ScanContext.ensure(ctx)
    dirs_found = find_existing_paths(base_url, WORDPRESS_DIRS, baseline, ctx)
    files_found = find_existing_paths(base_url, WORDPRESS_FILES, baseline, ctx)

    version = None
    version_entries = []

    # 1) readme.html: WordPress version + minimum PHP required by that
    #    core version. The content is required to mention "wordpress"
    #    (not just that the file exists with 200): a generic readme.html
    #    from other software could also carry a "Version X.X" line and
    #    would give a false positive if we only looked at the status code.
    resp = fetch_path(base_url, "readme.html", ctx)
    if resp is not None and resp.status_code == 200 and "wordpress" in resp.text.lower():
        m = re.search(r"Version\s+(\d+(?:\.\d+)*)", resp.text, re.IGNORECASE)
        if m:
            version = m.group(1)
            version_entries.append(f"readme.html -> WordPress {version}")
        min_php_required = extract_min_php_from_readme(resp.text)
        if min_php_required:
            version_entries.append(f"readme.html -> minimum PHP required: {min_php_required}")

    # 2) wp-includes/version.php (only gives something if the server is
    #    misconfigured and serves the PHP source code instead of
    #    executing it).
    resp = fetch_path(base_url, "wp-includes/version.php", ctx)
    if resp is not None and resp.status_code == 200:
        if version is None:
            m = re.search(r"\$wp_version\s*=\s*['\"](\d+(?:\.\d+)*(?:-[\w]+)?)['\"]", resp.text)
            if m:
                version = m.group(1)
                version_entries.append(f"wp-includes/version.php -> WordPress {version}")
        m_php = re.search(r"\$required_php_version\s*=\s*['\"](\d+(?:\.\d+)*)['\"]", resp.text)
        if m_php:
            version_entries.append(f"wp-includes/version.php -> minimum PHP required: {m_php.group(1)}")

    # 3) Home page meta generator (reuses home_resp if already requested)
    if version is None:
        resp = home_resp if home_resp is not None else safe_request("GET", base_url, session=ctx.session)
        if resp is not None and resp.status_code == 200:
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+(\d+(?:\.\d+)*)',
                resp.text, re.IGNORECASE,
            )
            if m:
                version = m.group(1)
                version_entries.append(f"/ (meta generator) -> WordPress {version}")

    # 4) RSS feed generator tag
    if version is None:
        resp = fetch_path(base_url, "feed/", ctx)
        if resp is not None and resp.status_code == 200:
            m = re.search(r"wordpress\.org/\?v=(\d+(?:\.\d+)*)", resp.text, re.IGNORECASE)
            if m:
                version = m.group(1)
                version_entries.append(f"feed/ (RSS generator) -> WordPress {version}")

    detected = bool(dirs_found or files_found or version_entries)
    if version:
        confidence = "strong"
    elif detected:
        confidence = "weak"
    else:
        confidence = "none"

    return {
        "dirs_found": dirs_found,
        "files_found": files_found,
        "version_entries": version_entries,
        "version": version,
        "detected": detected,
        "confidence": confidence,
    }


# --------------------------------------------------------------------------
# Drupal detection (default paths, split into STRONG/WEAK to avoid false
# positives):
#   - A single STRONG path/file (practically exclusive to Drupal) already
#     confirms it.
#   - WEAK paths/files (generic: "CHANGELOG.txt", "user/login"...) exist
#     in a lot of software that isn't Drupal, so a single hit there is
#     NOT enough: >= 2 distinct weak hits are required.
#   - check_drupal_detailed returns a dict with directories/files found
#     separately and the version (if identified in CHANGELOG.txt), to
#     feed the "Drupal" tab with full methodology traceability.
# --------------------------------------------------------------------------
def extract_drupal_version_from_changelog(text: str):
    """
    Looks in the content of CHANGELOG.txt/core/CHANGELOG.txt for Drupal's
    traditional header: "Drupal X.Y.Z, YYYY-MM-DD" (the first entry in
    the file is always the currently installed version).
    """
    m = re.search(r"Drupal\s+(\d+(?:\.\d+)*)\s*,\s*\d{4}-\d{2}-\d{2}", text, re.IGNORECASE)
    return m.group(1) if m else None


def check_drupal_headers(base_url: str, home_resp=None, ctx: "ScanContext" = None) -> list:
    """
    Looks for Drupal-specific markers in the home page's cookies/HTTP
    headers (independent of the default paths): SESS/SSESS session
    cookie, X-Generator: Drupal header, X-Drupal-Cache/
    X-Drupal-Dynamic-Cache headers. Returns a list of descriptive lines
    (one per marker found), for the "HTTP Headers" column of the
    "Drupal" tab. Any of these markers is, by itself, as strong as a
    Drupal-specific path.

    `home_resp` avoids repeating the GET to the home page already done
    by check_headers/check_cookies/scan_target.
    """
    ctx = ScanContext.ensure(ctx)
    findings = []
    resp = home_resp if home_resp is not None else safe_request("GET", base_url, session=ctx.session)
    if resp is None:
        return findings

    cookie_names = [c.name for c in resp.cookies]
    set_cookie_header = resp.headers.get("Set-Cookie", "")
    if any(re.match(r"S?SESS[0-9a-fA-F]{32}$", name) for name in cookie_names) or \
       re.search(r"\bS?SESS[0-9a-fA-F]{32}=", set_cookie_header):
        findings.append("SESS/SSESS session cookie")

    x_generator = resp.headers.get("X-Generator", "")
    if "drupal" in x_generator.lower():
        findings.append(f"X-Generator header: {x_generator}")

    if "X-Drupal-Cache" in resp.headers or "X-Drupal-Dynamic-Cache" in resp.headers:
        findings.append("X-Drupal-Cache/X-Drupal-Dynamic-Cache header")

    return findings


def check_drupal_detailed(base_url: str, home_resp=None, baseline=None, ctx: "ScanContext" = None) -> dict:
    """
    Checks for Drupal usage and returns EVERYTHING identified separately
    (same criteria as check_wordpress_detailed):

      "dirs_found":       list of accessible default directories
                          (strong + weak, with no distinction in this
                          list; the distinction is only used to compute
                          confidence).
      "files_found":      list of accessible default files (same).
      "headers_found":    list of Drupal-specific markers in the home
                          page's cookies/HTTP headers (see
                          check_drupal_headers), for the "HTTP Headers"
                          column of the "Drupal" tab.
      "version_entries":  list of "file -> identified data" lines with
                          the Drupal version, when it can be extracted
                          from CHANGELOG.txt/core/CHANGELOG.txt.
      "version":          the identified Drupal version, or None.
      "detected":          True if there is enough evidence (see the
                          strong/weak rules below).
      "confidence":        "strong" if there is >= 1 strong hit (strong
                          path/file, cookie/header marker, or confirmed
                          version); "weak" if there are only >= 2
                          distinct weak hits (generic paths/files);
                          "none" in any other case (including a single
                          isolated weak hit, which is not conclusive).

    `baseline` discards paths that are actually a generic catch-all from
    the server; `home_resp` avoids repeating the GET to the home page
    already done by check_headers/check_cookies.

    "core/CHANGELOG.txt"/"CHANGELOG.txt" are also in DRUPAL_WEAK_FILES
    (requested for the existence check that feeds "files_found"); here
    that same response is reused via ctx.cache (fetch_path) to extract
    the version instead of downloading them again.
    """
    ctx = ScanContext.ensure(ctx)
    strong_dirs = find_existing_paths(base_url, DRUPAL_STRONG_DIRS, baseline, ctx)
    strong_files = find_existing_paths(base_url, DRUPAL_STRONG_FILES, baseline, ctx)
    weak_dirs = find_existing_paths(base_url, DRUPAL_WEAK_DIRS, baseline, ctx)
    weak_files = find_existing_paths(base_url, DRUPAL_WEAK_FILES, baseline, ctx)

    dirs_found = strong_dirs + weak_dirs
    files_found = strong_files + weak_files

    headers_found = check_drupal_headers(base_url, home_resp, ctx)

    version = None
    version_entries = []
    for changelog_path in ("core/CHANGELOG.txt", "CHANGELOG.txt"):
        resp = fetch_path(base_url, changelog_path, ctx)
        if resp is not None and resp.status_code == 200:
            v = extract_drupal_version_from_changelog(resp.text)
            if v:
                version = v
                version_entries.append(f"{changelog_path} -> Drupal {version}")
                break

    strong_hits = len(strong_dirs) + len(strong_files) + len(headers_found)
    weak_hits = len(weak_dirs) + len(weak_files)

    if strong_hits >= 1 or version:
        confidence = "strong"
        detected = True
    elif weak_hits >= 2:
        confidence = "weak"
        detected = True
    else:
        confidence = "none"
        detected = False

    return {
        "dirs_found": dirs_found,
        "files_found": files_found,
        "headers_found": headers_found,
        "version_entries": version_entries,
        "version": version,
        "detected": detected,
        "confidence": confidence,
    }


def reconcile_cms_detections(result: dict, confidences: dict):
    """
    Prevents the same asset from being flagged "Yes" on both WordPress
    and Drupal at once due to a collision of generic paths: if both come
    out "Yes" and at least one has "strong" confidence, the one that only
    reached "Yes" with "weak" confidence is downgraded to "No". If both
    have "strong" confidence at the same time, both are left as-is: that
    is no longer a collision of generic paths, it is real coexistence to
    be reported and must not be hidden.
    """
    positives = [col for col in confidences if result.get(col) == "Yes"]
    if len(positives) <= 1:
        return
    strong = [col for col in positives if confidences[col] == "strong"]
    if not strong:
        return
    for col in positives:
        if col not in strong:
            result[col] = "No"


def check_php_default_dirs(base_url: str, baseline=None, ctx: "ScanContext" = None) -> str:
    """
    Tests a list of generic directories/files typical of PHP
    installations (vendor/, .env, includes/, phpmyadmin/, etc.), not tied
    to any specific CMS. Complements check_php_default and
    check_composer, which already cover their own specific cases.

    `baseline` discards paths that are actually a generic catch-all from
    the server (if they weren't discarded, a server that responds
    200/403 to any path would flag ALL these directories as "exposed").
    """
    findings = find_existing_paths(base_url, PHP_GENERIC_PATHS, baseline, ctx)
    return ", ".join(findings) if findings else "None exposed"


def check_favicon(base_url: str, ctx: "ScanContext" = None) -> str:
    """
    "Favicon" column: downloads favicon.ico and compares the MD5 of its
    raw content (bytes, not text) against FAVICON_MD5_HASHES, a list of
    default/un-customized hashes of known CMS and software (source:
    OWASP Favicon Database). A hash that DOES match is a strong signal
    (that exact, untouched favicon is that installation's); a hash that
    does NOT match is not evidence of anything: most likely the site has
    its own/custom favicon.
    """
    ctx = ScanContext.ensure(ctx)
    responses = fetch_paths_parallel(base_url, FAVICON_PATHS, ctx)
    for path in FAVICON_PATHS:
        resp = responses.get(path)
        if resp is None or resp.status_code != 200 or not resp.content:
            continue
        md5_hash = hashlib.md5(resp.content).hexdigest()
        software = FAVICON_MD5_HASHES.get(md5_hash)
        if software:
            return f"CMS/software detected: {software} (MD5: {md5_hash})"
        return f"Custom/unrecognized favicon (MD5: {md5_hash})"
    return "No accessible favicon.ico"


# --------------------------------------------------------------------------
# Derived intelligence flags ("Uses WP" / "Uses Drupal" / "Uses PHP").
# "Uses WP"/"Uses Drupal" and their confidence are obtained directly from
# the dicts returned by check_wordpress_detailed/check_drupal_detailed
# (see scan_target), with no need to re-parse any text.
# --------------------------------------------------------------------------


def has_direct_php_evidence(result: dict) -> bool:
    """
    DIRECT evidence of PHP already collected in the result's other
    columns (without launching new requests): a detected PHP version,
    exposed phpinfo/PHP error log, a README declaring a minimum required
    PHP version, exposed composer.json/lock, a favicon that matches a
    known CMS/software hash (all the entries of FAVICON_MD5_HASHES are
    PHP software), the word "php" in the nmap/whatweb output, or one of
    the generic PHP directories/files flagged as a strong signal
    (vendor/, .env...).
    """
    version_str, _source = extract_php_version_from_result(result)
    if version_str:
        return True

    phpinfo_col = result.get("Default PHP paths", "") or ""
    if "EXPOSED" in phpinfo_col or "minimum PHP required" in phpinfo_col:
        return True

    composer_col = result.get("composer.json/lock exposed", "") or ""
    if "EXPOSED" in composer_col:
        return True

    favicon_col = result.get("Favicon", "") or ""
    if favicon_col.startswith("CMS/software detected"):
        return True

    for col in ("HTTP Headers (X-Powered-By/Server)",
                "Nmap -sV (services/technologies + PHP)",
                "WhatWeb"):
        value = result.get(col, "") or ""
        if re.search(r"\bphp\b", value, re.IGNORECASE):
            return True

    dirs_col = result.get("Default PHP directories", "") or ""
    found = {d.strip() for d in dirs_col.split(",")}
    if found & PHP_GENERIC_STRONG_SIGNALS:
        return True

    return False


def flag_php(result: dict) -> str:
    """
    'Uses PHP' = Yes if WordPress or Drupal was detected (both are PHP by
    definition), OR if there is direct PHP evidence already collected in
    other columns.
    """
    cms_flags = ("Uses WP", "Uses Drupal")
    if any(result.get(flag) == "Yes" for flag in cms_flags):
        return "Yes"
    return "Yes" if has_direct_php_evidence(result) else "No"


def assign_priority(result: dict):
    """
    Mitigation priority level (1 = most critical, 4 = least critical),
    intended to sort the main sheet and tackle priority-1 assets first.
    The full criteria (also shown on the "Readme" tab) live in
    PRIORITY_CRITERIA; here only the EVALUATION order is applied, which
    is not the same as the NUMERIC order of the labels:

      1 - Confirmed vulnerable to CVE-2026-109618 / CVE-2026-109619 (the
          CVE column starts with "VULNERABLE"). Checked first, always
          wins over any other criterion.
      3 - WordPress or Drupal identified via headers, cookies, default
          directories or files specific to that CMS ("Uses WP" or "Uses
          Drupal" = "Yes"). Checked BEFORE 2 even though its label is
          higher: having confirmed a specific CMS is a more specific/
          useful signal than the merely generic "uses PHP" of criterion
          2, and both almost always coincide (a detected WP/Drupal also
          triggers "Uses PHP"), so 3 must be checked first so it is
          never eclipsed by 2.
      2 - Generic PHP usage ("Uses PHP" = "Yes") WITHOUT a specific CMS
          having been identified (neither WordPress nor Drupal):
          X-Powered-By header, exposed phpinfo/error log, exposed
          composer.json/lock, mention of PHP in nmap/whatweb, favicon of
          known PHP software, etc.
      4 - None of the above cases: no CVE, no CMS detected, no generic
          PHP evidence. This is the lowest priority level, but it is
          still a value for the column (it's no longer left blank/"-"),
          so that the asset is equally classified and sortable.
    """
    cve_status = str(result.get(CVE_COLUMN_NAME, "") or "")
    if cve_status.startswith("VULNERABLE"):
        return 1

    if result.get("Uses WP") == "Yes" or result.get("Uses Drupal") == "Yes":
        return 3

    if result.get("Uses PHP") == "Yes":
        return 2

    return 4


# Criteria for the "Priority" column, in NUMERIC order (1, 2, 3, 4),
# intended to be shown to the user on the "Readme" tab - this is NOT the
# evaluation order of assign_priority, which checks 3 before 2 (see
# assign_priority's docstring); here only the MEANING of each value is
# documented, not the order in which it is decided.
PRIORITY_CRITERIA = [
    (
        "1",
        "Confirmed vulnerable",
        "The asset is vulnerable to CVE-2026-109618 / CVE-2026-109619: a "
        "specific PHP version was identified and, when checked against "
        "the AWS bulletin, it turned out to be below the fixed version "
        "(or on an EOL branch with no patch available).",
    ),
    (
        "2",
        "Generic PHP usage",
        "There is evidence that the asset uses PHP (X-Powered-By header, "
        "exposed phpinfo or PHP error log, exposed composer.json/lock, "
        "mention of PHP in the nmap/whatweb output, favicon of known PHP "
        "software, etc.) but WITHOUT a specific CMS having been "
        "identified (neither WordPress nor Drupal).",
    ),
    (
        "3",
        "CMS identified (WordPress or Drupal)",
        "Headers, cookies, default directories or files specific to "
        "WordPress or Drupal have been identified, confirming the use of "
        "that technology (columns 'Uses WP' / 'Uses Drupal' = 'Yes'), "
        "regardless of whether the PHP version could also be identified.",
    ),
    (
        "4",
        "No evidence of PHP or of a CMS",
        "No evidence of PHP or of WordPress/Drupal was found for this "
        "asset. This is the lowest priority level.",
    ),
]

PRIORITY_CRITERIA_NOTE = (
    "Note on the evaluation order: if the same asset meets both criterion "
    "2 and criterion 3 at once (the usual case, since WordPress/Drupal "
    "run on PHP), it is assigned priority 3: having identified a specific "
    "CMS is a more specific and useful signal for mitigation than the "
    "mere generic use of PHP."
)

README_DISCLAIMER = (
    "This report (Excel and HTML) was generated with php_version_recon.py, "
    "a reconnaissance script intended ONLY for use in pentests or bug "
    "bounty programs with explicit authorization over the assets "
    "analyzed. Using this tool and this report without that authorization "
    "may be illegal."
)


def run_cmd(cmd: list, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout or "") + (result.stderr or "")
        return output.strip()[:2000] if output.strip() else "No output"
    except subprocess.TimeoutExpired:
        return "ERROR - timeout"
    except FileNotFoundError:
        return "N/A - tool not found"
    except Exception as e:
        return f"ERROR - {e}"


def run_nmap(host_port: str) -> str:
    """
    Launches nmap with -sV (service version detection: Apache, Nginx,
    OpenSSL, etc.) combined with the http-php-version script, so that
    both the PHP version and the rest of the technologies/versions
    detected on the scanned ports end up in the same cell.
    """
    if not tool_exists("nmap"):
        return "N/A - nmap not installed"

    out = run_cmd(
        ["nmap", "-sV", "--version-intensity", "5", "-p", "80,443",
         "--script", "http-php-version", host_port],
        timeout=150,  # -sV lengthens the scan, we give it more leeway than a plain nmap
    )

    relevant = []
    in_php_script_block = False
    for raw_line in out.splitlines():
        line = raw_line.strip()
        low = line.lower()

        # Port lines with service/version detected by -sV
        # (e.g. "80/tcp open  http  Apache httpd 2.4.41 ((Ubuntu))")
        if "/tcp" in low or "/udp" in low:
            relevant.append(line)
            in_php_script_block = False
            continue

        # Start of the http-php-version script's output block
        # (e.g. "| http-php-version:")
        if "php" in low:
            relevant.append(line)
            in_php_script_block = line.startswith("|") and not line.startswith("|_")
            continue

        # Continuation lines of the previous NSE script (start with | or
        # |_), such as "|_  Version: 7.4.3", which is where the actually
        # useful data comes from
        if in_php_script_block and line.startswith(("|", "|_")):
            relevant.append(line)
            if line.startswith("|_"):
                in_php_script_block = False
            continue

        # NOTE: the "Service Info" line that nmap adds with -sV (OS, CPE,
        # etc.) is intentionally discarded: it adds no value for
        # PHP/service fingerprinting and must not be written to the Excel.

    # One line break per detected service/finding, instead of
    # concatenating everything into a single line: more readable when
    # the app exposes several ports/services (e.g. 80 and 443 with
    # different versions).
    return "\n".join(relevant) if relevant else (out[:300] if out else "No output")


# ANSI color sequences, with or without the real ESC character (whatweb
# sometimes emits them even without a terminal, and depending on how the
# output is captured the ESC byte (\x1b) can be lost, leaving only
# literals like "[1m", "[0m]").
_ANSI_WITH_ESC_RE = re.compile(r"\x1b\[[0-9;]*m")
_ANSI_BARE_CODE_RE = re.compile(r"\[\d{1,3}(?:;\d{1,3})*m\]?")


def strip_ansi(text: str) -> str:
    text = _ANSI_WITH_ESC_RE.sub("", text)
    text = _ANSI_BARE_CODE_RE.sub("", text)
    return text


# Whatweb plugins that are NOT useful for server/technology fingerprinting
# (noise): discarded when filtering the output.
_WHATWEB_NOISE_PLUGINS = {
    "ip", "country", "title", "email", "redirectlocation",
    "uncommonheaders", "via-proxy", "allenum", "summary",
    "cookies", "x-frame-options", "strict-transport-security",
}


def _split_top_level(text: str, sep: str = ",") -> list:
    """Splits on commas that are OUTSIDE brackets, respecting that
    whatweb nests several [value] in a row for the same plugin
    (e.g. Country[UNITED STATES][US])."""
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
    Cleans the ANSI codes and keeps only the relevant server/technology
    plugins (Apache, nginx, PHP, HTTPServer, X-Powered-By, CMS, JS
    frameworks, etc.), discarding noise like IP, Country, Title...
    """
    text = strip_ansi(raw).strip()
    if not text:
        return "No output"

    # The URL and the status code ([200 OK]) go at the start of the line;
    # the rest, after the first "] ", are the detected plugins.
    marker = "] "
    idx = text.find(marker)
    plugins_part = text[idx + len(marker):] if idx != -1 else text

    tokens = _split_top_level(plugins_part)
    useful = []
    for token in tokens:
        plugin_name = token.split("[", 1)[0].strip().lower()
        if plugin_name in _WHATWEB_NOISE_PLUGINS:
            continue
        useful.append(token)

    return ", ".join(useful) if useful else "No relevant technologies detected"


def run_whatweb(base_url: str) -> str:
    if not tool_exists("whatweb"):
        return "N/A - whatweb not installed"
    out = run_cmd(
        ["whatweb", "-a", "3", "--no-errors", "--color=never", base_url],
        timeout=60,
    )
    cleaned = parse_whatweb_output(out)
    return cleaned[:800]


def run_nikto(base_url: str) -> str:
    if not tool_exists("nikto"):
        return "N/A - nikto not installed"
    out = run_cmd(["nikto", "-h", base_url, "-Tuning", "9"], timeout=180)
    lines = [l for l in out.splitlines() if "php" in l.lower()]
    return " | ".join(lines[:10]) if lines else "No relevant PHP findings"


def run_nuclei(base_url: str) -> str:
    if not tool_exists("nuclei"):
        return "N/A - nuclei not installed"
    out = run_cmd(["nuclei", "-u", base_url, "-t", "technologies/", "-silent"], timeout=180)
    return out[:800] if out else "No findings"


# --------------------------------------------------------------------------
# Per-asset orchestration
# --------------------------------------------------------------------------
def extract_host_port(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else url


def scan_target(url: str, full: bool, path_concurrency: int = PER_ASSET_CONCURRENCY) -> dict:
    """
    `path_concurrency`: number of concurrent requests when checking lists
    of default paths WITHIN this asset (see ScanContext). Comes from
    --path-threads; not to be confused with the parallelism BETWEEN
    different assets (--threads), which is handled in main() by the
    ThreadPoolExecutor that calls this function.
    """
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http"):
        url = "http://" + url

    log(f"[*] Scanning {url} ...")

    # A single requests.Session per asset: reuses the TCP/TLS connection
    # (keep-alive) across the dozens of GET requests launched against the
    # same host, instead of opening a new connection for each one. It is
    # always closed when done (even if the asset is SSO or an exception
    # is raised), hence the try/finally.
    session = requests.Session()
    ctx = ScanContext(session=session, max_workers=path_concurrency)
    try:
        final_url, chain = resolve_redirect_chain(url, ctx=ctx)
        if len(chain) > 1:
            redirect_summary = " -> ".join(chain)
            log(f"    [>] Redirected: {redirect_summary}")
        else:
            redirect_summary = "No redirection"

        if is_sso_redirect(final_url):
            log(
                f"    [i] {url} redirects to corporate SSO ({final_url}) "
                f"- skipping the rest of the tests, continuing with the next asset"
            )
            skipped = "-"
            # For SSO we don't show the full URI (it may carry long,
            # irrelevant OAuth parameters), only the IdP's subdomain.
            sso_host = urlparse(final_url).netloc.split(":")[0]
            result = {
                # Internal marker (not a column): allows moving these rows
                # to the O365 tab instead of the main sheet. Filtered out
                # when writing the Excel, never shown as a visible column.
                "_sso": True,
                "Priority": skipped,
                "Asset": url,
                "Final URL (after redirects)": sso_host,
                "HTTP Headers (X-Powered-By/Server)": skipped,
                "Session cookies": skipped,
                "Default PHP paths": skipped,
                "composer.json/lock exposed": skipped,
                "WordPress": skipped,
                "Drupal": skipped,
                "Favicon": skipped,
                "CVE-2026-109618 / CVE-2026-109619": skipped,
                "Nmap -sV (services/technologies + PHP)": skipped,
                "WhatWeb": skipped,
                "Default PHP directories": skipped,
                "Uses WP": skipped,
                "Uses Drupal": skipped,
                "Uses PHP": skipped,
            }
            if full:
                result["Nikto (PHP findings)"] = skipped
                result["Nuclei technologies"] = skipped
            return result

        # From here on, ALL tests are run against final_url, which is
        # where the application actually lives after following the 30x
        # redirects.
        host_port = extract_host_port(final_url)

        # Two optimizations/anti-false-positive measures computed ONCE
        # per asset and reused across several check_* functions, instead
        # of repeating the same request:
        #   - home_resp: the GET to the home page needed by
        #     check_headers, check_cookies, check_wordpress (meta
        #     generator) and check_drupal (cookies/headers). It used to
        #     be requested separately in each one.
        #   - baseline: response to a path that surely doesn't exist, so
        #     that the default-path checks (WordPress, Drupal, generic
        #     PHP directories) don't mistake a "catch-all" server
        #     (200/403 for any path) for those paths really existing.
        home_resp = safe_request("GET", final_url, session=session)
        baseline = get_baseline_response(final_url, ctx)

        # WordPress/Drupal are checked with the "_detailed" functions,
        # which return EVERYTHING identified separately (directories,
        # files, version with the exact file it came from). This allows
        # the visible "WordPress"/"Drupal" column on the main sheet to be
        # left with just the version (the conclusion), while the full
        # detail (the methodology/traceability) is kept in internal
        # "_wp_*"/"_drupal_*" keys to feed the "WP"/"Drupal" tabs. Both
        # share the same ctx (same session + same path cache), so a path
        # requested by one is not requested again for the other.
        wp_detailed = check_wordpress_detailed(final_url, home_resp, baseline, ctx)
        drupal_detailed = check_drupal_detailed(final_url, home_resp, baseline, ctx)

        result = {
            # Actual value assigned at the end (assign_priority needs the
            # CVE, "Uses WP" and "Uses Drupal" already computed); it is
            # initialized here only to fix this column as the FIRST one
            # on the main sheet.
            "Priority": None,
            "Asset": url,
            "Final URL (after redirects)": final_url,
            "HTTP Headers (X-Powered-By/Server)": check_headers(final_url, home_resp, ctx),
            "Session cookies": check_cookies(final_url, home_resp, ctx),
            "Default PHP paths": check_php_default(final_url, baseline, ctx),
            "composer.json/lock exposed": check_composer(final_url, ctx),
            "WordPress": wp_detailed["version"] if wp_detailed["version"] else "Not detected",
            "Drupal": drupal_detailed["version"] if drupal_detailed["version"] else "Not detected",
            "Favicon": check_favicon(final_url, ctx),
            "Nmap -sV (services/technologies + PHP)": run_nmap(host_port),
            "WhatWeb": run_whatweb(final_url),
            # Internal markers (not columns, filtered out when writing the
            # Excel): feed the "WP"/"Drupal" tabs with Directories, Files
            # and Version separately.
            "_wp_dirs": wp_detailed["dirs_found"],
            "_wp_files": wp_detailed["files_found"],
            "_wp_version_entries": wp_detailed["version_entries"],
            "_drupal_dirs": drupal_detailed["dirs_found"],
            "_drupal_files": drupal_detailed["files_found"],
            "_drupal_headers": drupal_detailed["headers_found"],
            "_drupal_version_entries": drupal_detailed["version_entries"],
        }

        # This column is computed from the PHP version already detected
        # above (in several columns), without launching any new request.
        result["CVE-2026-109618 / CVE-2026-109619"] = check_php_cve(result)

        # Analysis of generic directories/files typical of PHP
        # installations (vendor/, .env, includes/, etc.), independent of
        # any CMS.
        result["Default PHP directories"] = check_php_default_dirs(final_url, baseline, ctx)

        # Technology intelligence: WP/Drupal confidence comes straight
        # from the dicts already computed above, without re-parsing any
        # text. It is used right after to reconcile a possible false
        # positive when WordPress and Drupal both come out "Yes" on the
        # same asset due to a collision of generic paths (see
        # reconcile_cms_detections).
        result["Uses WP"] = "Yes" if wp_detailed["detected"] else "No"
        result["Uses Drupal"] = "Yes" if drupal_detailed["detected"] else "No"

        reconcile_cms_detections(result, {
            "Uses WP": wp_detailed["confidence"],
            "Uses Drupal": drupal_detailed["confidence"],
        })

        # "Uses PHP" is computed last, once WP and Drupal are reconciled.
        result["Uses PHP"] = flag_php(result)

        # "Priority" depends on the CVE and on "Uses WP"/"Uses Drupal"/
        # "Uses PHP" already reconciled/computed above, so it is assigned
        # here (the "None" above only fixed the column's position).
        result["Priority"] = assign_priority(result)

        if full:
            result["Nikto (PHP findings)"] = run_nikto(final_url)
            result["Nuclei technologies"] = run_nuclei(final_url)

        return result
    finally:
        session.close()


# --------------------------------------------------------------------------
# Excel
# --------------------------------------------------------------------------
EXCEL_MAX_CELL_CHARS = 32767  # Excel's hard per-cell limit
FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")

# Styles shared by ALL tabs (Readme, Dashboard, PHP Recon, WP, Drupal,
# O365): each function that used to write a sheet (_write_table_to_sheet,
# build_dashboard_sheet, build_readme_sheet) used to create its own
# identical Font/PatternFill objects on its own (same corporate color
# "6B5B46", a muted warm brown/taupe); openpyxl allows reusing the same
# style instance across many cells without problems, so they are defined
# once here.
EXCEL_TITLE_FONT = Font(bold=True, size=14, color="6B5B46")
EXCEL_HEADER_FONT = Font(bold=True, color="FFFCF5")
EXCEL_HEADER_FILL = PatternFill(start_color="6B5B46", end_color="6B5B46", fill_type="solid")
EXCEL_LABEL_FONT = Font(bold=True)
EXCEL_HEADER_ALIGNMENT = Alignment(horizontal="center", vertical="center", wrap_text=True)


def _apply_header_style(cell):
    """Applies the common header style (blue background, bold white text,
    centered with wrap) to a cell on any tab."""
    cell.font = EXCEL_HEADER_FONT
    cell.fill = EXCEL_HEADER_FILL
    cell.alignment = EXCEL_HEADER_ALIGNMENT


def sanitize_cell_value(value):
    """
    Leaves a value ready to be written into an Excel cell without causing:
      1) openpyxl's IllegalCharacterError (control characters not valid
         in XML, e.g. null bytes or control bytes that sometimes appear
         in raw HTTP responses, nmap/whatweb/nikto outputs, etc.).
      2) Silent corruption/truncation from exceeding Excel's 32767
         character per-cell limit.
      3) Formula injection (CSV/Excel Formula Injection): if the content
         comes from an untrusted external source (e.g. a Set-Cookie or
         X-Powered-By manipulated by the scanned target itself) and
         starts with =, +, - or @, Excel might interpret it as a formula
         when opening the file. It is neutralized by prefixing an
         apostrophe, which forces plain text.
    """
    if value is None:
        return ""

    text = str(value)

    # 1) Remove characters illegal for XML/XLSX
    text = ILLEGAL_CHARACTERS_RE.sub("", text)
    # Also clean up stray line breaks that sometimes break the layout
    text = text.replace("\x00", "")

    # 2) Neutralize possible formula injection
    if text and text[0] in FORMULA_TRIGGER_CHARS:
        text = "'" + text

    # 3) Trim to Excel's limit, leaving a note of the trim
    if len(text) > EXCEL_MAX_CELL_CHARS:
        suffix = " ...[TRUNCATED]"
        text = text[: EXCEL_MAX_CELL_CHARS - len(suffix)] + suffix

    return text




def _write_table_to_sheet(ws, columns: list, rows: list) -> int:
    """
    Writes a table (header + rows) into an already-created sheet, with
    the same formatting (colors, wrap, sanitization) on all the
    document's tabs. Returns the number of cells that had to be replaced
    with illegal characters, so the caller can accumulate the total.
    """
    for col_idx, col_name in enumerate(columns, start=1):
        cell = ws.cell(row=1, column=col_idx, value=sanitize_cell_value(col_name))
        _apply_header_style(cell)

    skipped_cells = 0
    for row_idx, row_data in enumerate(rows, start=2):
        for col_idx, col_name in enumerate(columns, start=1):
            raw_value = row_data.get(col_name, "")
            safe_value = sanitize_cell_value(raw_value)
            try:
                cell = ws.cell(row=row_idx, column=col_idx, value=safe_value)
            except IllegalCharacterError:
                # Safety net in case something slips through despite the
                # sanitization: we don't abort the whole report for a
                # single problematic cell.
                cell = ws.cell(
                    row=row_idx, column=col_idx,
                    value="[CONTENT OMITTED - characters not valid for Excel]",
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
# Readme tab: authorized-use disclaimer + criteria for the "Priority"
# column (PRIORITY_CRITERIA/PRIORITY_CRITERIA_NOTE), so that whoever opens
# the report knows at a glance what each value means without having to
# ask or read the source code.
# --------------------------------------------------------------------------
def build_readme_sheet(wb, ws=None):
    if ws is None:
        ws = wb.create_sheet("Readme")

    wrap_top = Alignment(wrap_text=True, vertical="top")

    ws["A1"] = "PHP/CMS reconnaissance report"
    ws["A1"].font = EXCEL_TITLE_FONT

    ws["A3"] = README_DISCLAIMER
    ws["A3"].alignment = wrap_top
    ws.merge_cells("A3:D3")
    ws.row_dimensions[3].height = 45

    ws["A5"] = "Criteria for the \"Priority\" column"
    ws["A5"].font = EXCEL_TITLE_FONT

    headers = ["Priority", "Criterion", "Description"]
    header_row = 6
    for col_idx, h in enumerate(headers, start=1):
        _apply_header_style(ws.cell(row=header_row, column=col_idx, value=h))

    for offset, (priority, criterion, description) in enumerate(PRIORITY_CRITERIA):
        row = header_row + 1 + offset
        ws.cell(row=row, column=1, value=priority).alignment = Alignment(horizontal="center", vertical="top")
        ws.cell(row=row, column=2, value=criterion).alignment = wrap_top
        ws.cell(row=row, column=3, value=description).alignment = wrap_top

    note_row = header_row + 1 + len(PRIORITY_CRITERIA) + 1
    ws.cell(row=note_row, column=1, value=PRIORITY_CRITERIA_NOTE).alignment = wrap_top
    ws.merge_cells(f"A{note_row}:D{note_row}")
    ws.row_dimensions[note_row].height = 60

    ws.column_dimensions["A"].width = 12
    ws.column_dimensions["B"].width = 32
    ws.column_dimensions["C"].width = 75
    ws.column_dimensions["D"].width = 20


# --------------------------------------------------------------------------
# Dashboard tab: metrics table + native Excel pie charts (linked to the
# table's own cells, so therefore dynamic: if someone edits a table cell
# by hand, the chart updates itself).
# --------------------------------------------------------------------------
DASHBOARD_METRICS = [
    # (label, function that decides whether a row "meets" the metric)
    (
        "Vulnerable to CVE-2026-109618 / CVE-2026-109619 (PHP)",
        lambda r: str(r.get(CVE_COLUMN_NAME, "")).startswith("VULNERABLE"),
    ),
    ("Use WordPress", lambda r: r.get("Uses WP") == "Yes"),
    ("Use Drupal", lambda r: r.get("Uses Drupal") == "Yes"),
    ("Use PHP", lambda r: r.get("Uses PHP") == "Yes"),
]


def compute_dashboard_stats(normal_rows: list, sso_rows: list) -> dict:
    """
    Computes ALL the numbers/lists the Dashboard needs (summary,
    DASHBOARD_METRICS metrics and the CVE breakdown), so that
    build_dashboard_sheet (Excel) and build_dashboard_html_data (HTML)
    consume the same data instead of each one recomputing the same logic
    on its own (vulnerable_rows/no_vulnerable_rows/indeterminate_count
    and the metrics loop, previously duplicated).

    Returns "raw" rows (full dicts, not already-formatted strings) so
    that each consumer decides how to present them: build_dashboard_sheet
    sanitizes them for Excel, build_dashboard_html_data passes them
    through _stringify_for_html.
    """
    total_evaluated = len(normal_rows)

    metrics = []
    for label, predicate in DASHBOARD_METRICS:
        meet = sum(1 for r in normal_rows if predicate(r))
        do_not_meet = total_evaluated - meet
        pct = round((meet / total_evaluated * 100), 1) if total_evaluated else 0.0
        metrics.append({
            "label": label, "meet": meet, "not_meet": do_not_meet,
            "total": total_evaluated, "pct": pct,
        })

    vulnerable_rows = [
        r for r in normal_rows
        if str(r.get(CVE_COLUMN_NAME, "")).startswith("VULNERABLE")
    ]
    no_vulnerable_rows = [
        r for r in normal_rows
        if str(r.get(CVE_COLUMN_NAME, "")).startswith("Not vulnerable")
    ]
    indeterminate_count = total_evaluated - len(vulnerable_rows) - len(no_vulnerable_rows)

    return {
        "total_general": len(normal_rows) + len(sso_rows),
        "total_evaluados": total_evaluated,
        "metrics": metrics,
        "vulnerable_rows": vulnerable_rows,
        "no_vulnerable_rows": no_vulnerable_rows,
        "indeterminado_count": indeterminate_count,
    }


def build_dashboard_sheet(wb, normal_rows: list, sso_rows: list, ws=None):
    """
    `ws`: already-created sheet where the Dashboard is built (so that the
    Workbook's default active sheet can be reused and renamed, guaranteeing
    that the Dashboard ends up as the FIRST tab without having to reorder
    sheets afterwards). If not passed, a new sheet called "Dashboard" is
    created (previous behavior, used by the existing tests).
    """
    if ws is None:
        ws = wb.create_sheet("Dashboard")

    # A single source of truth for the Dashboard's numbers/lists, shared
    # with build_dashboard_html_data (see compute_dashboard_stats): this
    # prevents Excel and HTML from ever showing different figures if this
    # logic is changed in one place someday and the other is forgotten.
    stats = compute_dashboard_stats(normal_rows, sso_rows)

    ws["A1"] = "Asset summary"
    ws["A1"].font = EXCEL_TITLE_FONT

    summary = [
        ("Total assets analyzed", stats["total_general"]),
        ("Assets evaluated (not redirected to SSO)", len(normal_rows)),
        ("Assets redirected to SSO (see O365 tab)", len(sso_rows)),
    ]
    for i, (label, value) in enumerate(summary, start=2):
        ws.cell(row=i, column=1, value=label).font = EXCEL_LABEL_FONT
        ws.cell(row=i, column=2, value=value)

    # Metrics table: each row feeds its chart directly.
    table_header_row = 6
    headers = ["Metric", "Meet", "Don't meet", "Total evaluated", "% of total"]
    for col_idx, h in enumerate(headers, start=1):
        _apply_header_style(ws.cell(row=table_header_row, column=col_idx, value=h))

    total_evaluados = stats["total_evaluados"]
    first_data_row = table_header_row + 1
    for offset, metric in enumerate(stats["metrics"]):
        row = first_data_row + offset
        ws.cell(row=row, column=1, value=metric["label"])
        ws.cell(row=row, column=2, value=metric["meet"])
        ws.cell(row=row, column=3, value=metric["not_meet"])
        ws.cell(row=row, column=4, value=metric["total"])
        # Native Excel formula (not a fixed value), so the % also
        # recalculates itself if someone edits the table by hand.
        ws.cell(row=row, column=5, value=f"=IF(D{row}=0,0,B{row}/D{row})")
        ws.cell(row=row, column=5).number_format = "0.0%"

    ws.column_dimensions["A"].width = 55
    for col in "BCDE":
        ws.column_dimensions[col].width = 16

    if total_evaluados == 0:
        ws.cell(
            row=first_data_row + len(DASHBOARD_METRICS) + 1, column=1,
            value="No assets evaluated (all redirected to SSO): no charts are generated.",
        )
        return

    # One pie chart (Meet vs Don't meet) per metric, linked to its table
    # row -> this is a native, dynamic Excel chart, not a static image.
    #
    # IMPORTANT: the two values (Meet, Don't meet) are in TWO COLUMNS of
    # ONE SAME ROW. openpyxl interprets a Reference by columns by default
    # (from_rows=False): with that, each column would be treated as a
    # DIFFERENT SERIES of a single point (2 series of 1 value each)
    # instead of ONE series with 2 values -> the pie chart came out
    # malformed (series and categories misaligned). from_rows=True tells
    # it to read the row as a single series with its 2 values.
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
    # Additional breakdown specific to CVE-2026-109618 / CVE-2026-109619:
    # a bar chart with 3 categories (Vulnerable / Not vulnerable /
    # Indeterminate) instead of just "Meet/Don't meet" from the pie chart
    # above, so as not to confuse "confirmed safe" with "could not
    # determine the PHP version" (the pie chart above lumps both cases
    # into the same "Don't meet"). Below it, the list of the specific
    # domains/assets affected, to identify them without having to filter
    # the main sheet by hand.
    # ----------------------------------------------------------------------
    vulnerable_rows = stats["vulnerable_rows"]
    no_vulnerable_rows = stats["no_vulnerable_rows"]
    indeterminado_count = stats["indeterminado_count"]

    breakdown_header_row = first_data_row + len(DASHBOARD_METRICS) + 2
    ws.cell(row=breakdown_header_row - 1, column=1,
            value="CVE-2026-109618 / CVE-2026-109619 breakdown").font = EXCEL_TITLE_FONT

    breakdown_headers = ["Status against the CVE", "Number of assets"]
    for col_idx, h in enumerate(breakdown_headers, start=1):
        _apply_header_style(ws.cell(row=breakdown_header_row, column=col_idx, value=h))

    breakdown_data = [
        ("Vulnerable", len(vulnerable_rows)),
        ("Not vulnerable (safe version)", len(no_vulnerable_rows)),
        ("Indeterminate (no PHP version detected)", indeterminado_count),
    ]
    breakdown_first_row = breakdown_header_row + 1
    for offset, (label, value) in enumerate(breakdown_data):
        row = breakdown_first_row + offset
        ws.cell(row=row, column=1, value=label)
        ws.cell(row=row, column=2, value=value)
    breakdown_last_row = breakdown_first_row + len(breakdown_data) - 1

    # Bar chart (not a pie, to visually distinguish it from the ones
    # above) with the breakdown's 3 categories. Same from_rows/from_cols
    # logic as the pie charts: here the data is in a COLUMN
    # (B{first}:B{last}), which is exactly add_data's default case
    # (from_rows=False), so there's no need to touch it.
    bar = BarChart()
    bar.type = "col"
    bar.title = "Assets against the CVE (breakdown)"
    bar.y_axis.title = "Number of assets"
    bar_data = Reference(ws, min_col=2, min_row=breakdown_header_row, max_row=breakdown_last_row)
    bar_cats = Reference(ws, min_col=1, min_row=breakdown_first_row, max_row=breakdown_last_row)
    bar.add_data(bar_data, titles_from_data=True)
    bar.set_categories(bar_cats)
    bar.legend = None
    bar.height = 7
    bar.width = 11
    bar_anchor_row = chart_anchor_rows[-1] + 16
    ws.add_chart(bar, f"G{bar_anchor_row}")

    # List of the specific vulnerable assets (domain + detail).
    domains_header_row = breakdown_last_row + 3
    ws.cell(row=domains_header_row - 1, column=1,
            value="Assets vulnerable to CVE-2026-109618 / CVE-2026-109619").font = EXCEL_TITLE_FONT

    if not vulnerable_rows:
        ws.cell(row=domains_header_row, column=1,
                value="No vulnerable asset detected.")
    else:
        domains_headers = ["Asset", "Final URL (after redirects)", "Detail"]
        for col_idx, h in enumerate(domains_headers, start=1):
            _apply_header_style(ws.cell(row=domains_header_row, column=col_idx, value=h))
        for offset, r in enumerate(vulnerable_rows):
            row = domains_header_row + 1 + offset
            ws.cell(row=row, column=1, value=sanitize_cell_value(r.get("Asset", "")))
            ws.cell(row=row, column=2, value=sanitize_cell_value(r.get("Final URL (after redirects)", "")))
            ws.cell(row=row, column=3, value=sanitize_cell_value(r.get(CVE_COLUMN_NAME, "")))
            ws.cell(row=row, column=3).alignment = Alignment(vertical="top", wrap_text=True)


def _build_cms_sheet_rows(normal_rows: list, dirs_key: str, files_key: str,
                           version_entries_key: str, headers_key: str = None) -> list:
    """
    Builds the rows for the "WP"/"Drupal" tabs from the internal
    "_wp_*"/"_drupal_*" keys that scan_target left in each result. Each
    list is joined with a line break (the same format already used in
    columns like "Default PHP paths"/"Default PHP directories"), with a
    fallback text when there is nothing to show.

    `headers_key` is optional: when given (only the "Drupal" tab uses it),
    the "HTTP Headers" column is added with the specific cookie/header
    markers found on the asset's home page.

    An asset is INCLUDED ONLY if something was identified in at least one
    of these columns (directories, files, headers/cookies or version): an
    asset with no findings doesn't contribute anything to the WP/Drupal
    traceability and would only add noise ("None accessible" in every
    column); those assets still appear in "PHP Recon" (which lists ALL
    assets), just not on these detail tabs.
    """
    sheet_rows = []
    for r in normal_rows:
        dirs = r.get(dirs_key) or []
        files = r.get(files_key) or []
        version_entries = r.get(version_entries_key) or []
        headers = r.get(headers_key) or [] if headers_key is not None else []

        if not (dirs or files or version_entries or headers):
            continue

        row = {
            "Asset": r.get("Asset", ""),
            "Final URL (after redirects)": r.get("Final URL (after redirects)", ""),
            "Directories": "\n".join(dirs) if dirs else "None accessible",
            "Files": "\n".join(files) if files else "None accessible",
        }
        if headers_key is not None:
            row["HTTP Headers"] = "\n".join(headers) if headers else "No specific header/cookie detected"
        row["Version"] = "\n".join(version_entries) if version_entries else "Not identified"
        sheet_rows.append(row)
    return sheet_rows


def _dataset_for_sheets(results: list) -> dict:
    """
    Centralizes the data preparation for ALL tabs (splitting SSO/normal,
    visible columns, WP/Drupal rows) in one place, so that write_excel and
    write_html (the equivalent HTML report) start from exactly the same
    data instead of duplicating this logic in two different functions and
    risking a future change desynchronizing them.
    """
    # Rows flagged with _sso (redirected to a corporate IdP, e.g.
    # login.microsoftonline.com) are MOVED to the O365 tab: they weren't
    # evaluated, so they add nothing useful to the main sheet, to the
    # WP/Drupal tabs or to the Dashboard.
    normal_rows = [r for r in results if not r.get("_sso")]
    sso_rows = [r for r in results if r.get("_sso")]

    # Visible columns: the same for both detail tabs (main and O365),
    # excluding internal markers (keys starting with "_", like "_sso" or
    # "_wp_dirs"/"_drupal_dirs"/etc.).
    sample_row = normal_rows[0] if normal_rows else (sso_rows[0] if sso_rows else {"Asset": ""})
    columns = [k for k in sample_row.keys() if not k.startswith("_")]

    # "WP"/"Drupal" tabs: methodology traceability (which default
    # directories/files could be accessed, and in which files the
    # version was identified), separate from the conclusion (version
    # only) that stays in the "WordPress"/"Drupal" column of the main
    # sheet.
    wp_columns = ["Asset", "Final URL (after redirects)", "Directories", "Files", "Version"]
    wp_rows = _build_cms_sheet_rows(normal_rows, "_wp_dirs", "_wp_files", "_wp_version_entries")

    # The "Drupal" tab adds an "HTTP Headers" column (specific cookie/
    # header markers: SESS/SSESS cookie, X-Generator,
    # X-Drupal-Cache/X-Drupal-Dynamic-Cache), which doesn't apply to
    # WordPress.
    drupal_columns = ["Asset", "Final URL (after redirects)", "Directories", "Files", "HTTP Headers", "Version"]
    drupal_rows = _build_cms_sheet_rows(
        normal_rows, "_drupal_dirs", "_drupal_files", "_drupal_version_entries",
        headers_key="_drupal_headers",
    )

    return {
        "normal_rows": normal_rows,
        "sso_rows": sso_rows,
        "columns": columns,
        "wp_columns": wp_columns,
        "wp_rows": wp_rows,
        "drupal_columns": drupal_columns,
        "drupal_rows": drupal_rows,
    }


def write_excel(results: list, output_path: str):
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    data = _dataset_for_sheets(results)
    normal_rows = data["normal_rows"]
    sso_rows = data["sso_rows"]
    columns = data["columns"]

    wb = Workbook()

    # Tab order: Readme, Dashboard, PHP Recon, WP, Drupal, O365. So that
    # "Readme" ends up FIRST without having to reorder sheets afterwards,
    # the Workbook's default active sheet is reused and renamed, and the
    # rest of the tabs are created from there in the desired order.
    ws_readme = wb.active
    ws_readme.title = "Readme"
    build_readme_sheet(wb, ws=ws_readme)

    ws_dashboard = wb.create_sheet("Dashboard")
    build_dashboard_sheet(wb, normal_rows, sso_rows, ws=ws_dashboard)

    ws_main = wb.create_sheet("PHP Recon")
    skipped_cells = _write_table_to_sheet(ws_main, columns, normal_rows)

    # "WP"/"Drupal" only list assets with SOME indication (directories,
    # files, headers/cookies or version) of that technology -see the
    # filter in _build_cms_sheet_rows-, so they can come out empty even
    # if "PHP Recon" (which lists ALL assets) isn't.
    ws_wp = wb.create_sheet("WP")
    skipped_cells += _write_table_to_sheet(ws_wp, data["wp_columns"], data["wp_rows"])
    if not data["wp_rows"]:
        ws_wp.cell(row=2, column=1, value="No asset with indications of WordPress (directories, files or version).")

    ws_drupal = wb.create_sheet("Drupal")
    skipped_cells += _write_table_to_sheet(ws_drupal, data["drupal_columns"], data["drupal_rows"])
    if not data["drupal_rows"]:
        ws_drupal.cell(row=2, column=1, value="No asset with indications of Drupal (headers, directories, files or version).")

    # "O365" tab: assets whose redirection led to a corporate login
    # (Microsoft 365 / Entra ID). Same columns as the main sheet, so it's
    # clear that each row is the same format, only that everything except
    # Asset/Final URL was left unevaluated ("-").
    ws_o365 = wb.create_sheet("O365")
    skipped_cells += _write_table_to_sheet(ws_o365, columns, sso_rows)
    if not sso_rows:
        ws_o365.cell(row=2, column=1, value="No asset redirected to a corporate (SSO) login.")

    if skipped_cells:
        print(
            f"[!] {skipped_cells} cell(s) had invalid characters and were "
            f"replaced with a notice so as not to break the Excel file.",
            file=sys.stderr,
        )

    wb.save(output_path)

    if not os.path.isfile(output_path):
        print(f"[!] ERROR: the file {output_path} was not created correctly.", file=sys.stderr)
        sys.exit(1)

    size_kb = os.path.getsize(output_path) / 1024
    print(
        f"[+] Excel generated successfully: {output_path} "
        f"({len(normal_rows)} rows evaluated x {len(columns)} columns in 'PHP Recon'; "
        f"{len(sso_rows)} asset(s) moved to 'O365'; 'Readme', 'Dashboard', 'WP' and 'Drupal' tabs generated; "
        f"{size_kb:.1f} KB)",
        file=sys.stderr,
    )


# --------------------------------------------------------------------------
# HTML report (equivalent to the Excel): same tabs and same data
# (_dataset_for_sheets), self-contained in a single file (inline CSS/JS,
# no external dependencies), with sortable columns and a search box that
# filters the rows of the active tab. Useful for reviewing the results in
# a browser without needing to open Excel.
# --------------------------------------------------------------------------
def _stringify_for_html(value) -> str:
    """
    Same as sanitize_cell_value but WITHOUT the Excel-specific escaping
    (the formula anti-injection prefixes an apostrophe, which makes no
    sense outside a spreadsheet and would show up as stray text in the
    HTML). The HTML is built via textContent/createElement in JS (see
    _HTML_TEMPLATE), never with innerHTML, so there's no need to escape
    tags here: the DOM itself prevents any injection even if the content
    (e.g. an HTTP header manipulated by the scanned target) contains
    "<script>" or other markup.
    """
    return "" if value is None else str(value)


def _rows_as_lists(columns: list, rows: list) -> list:
    """Converts a list of dicts {column: value} into lists of values in
    the same order as `columns`, the format the JS table consumes."""
    return [[_stringify_for_html(row.get(col, "")) for col in columns] for row in rows]


def build_readme_html_data() -> dict:
    """
    HTML equivalent of build_readme_sheet: same disclaimer and same
    criteria for the "Priority" column (PRIORITY_CRITERIA/
    PRIORITY_CRITERIA_NOTE), as plain data so write_html can render them
    without depending on openpyxl.
    """
    return {
        "disclaimer": README_DISCLAIMER,
        "criteria": [
            {"priority": p, "criterion": c, "description": d}
            for (p, c, d) in PRIORITY_CRITERIA
        ],
        "note": PRIORITY_CRITERIA_NOTE,
    }


def build_dashboard_html_data(normal_rows: list, sso_rows: list) -> dict:
    """
    Same information as build_dashboard_sheet (summary, metrics table,
    CVE breakdown and list of vulnerable assets), in a simple data
    structure (without openpyxl) so write_html can render it with plain
    HTML/CSS/JS. Consumes compute_dashboard_stats, the SAME source of
    truth used by build_dashboard_sheet for the Excel, so that both files
    always show the same numbers (previously each one separately
    recomputed vulnerable_rows/no_vulnerable_rows/indeterminate_count and
    the metrics loop).
    """
    stats = compute_dashboard_stats(normal_rows, sso_rows)

    summary = [
        {"label": "Total assets analyzed", "value": stats["total_general"]},
        {"label": "Assets evaluated (not redirected to SSO)", "value": len(normal_rows)},
        {"label": "Assets redirected to SSO (see O365 tab)", "value": len(sso_rows)},
    ]

    vulnerable_rows = stats["vulnerable_rows"]

    cve_breakdown = [
        {"label": "Vulnerable", "count": len(vulnerable_rows)},
        {"label": "Not vulnerable (safe version)", "count": len(stats["no_vulnerable_rows"])},
        {"label": "Indeterminate (no PHP version detected)", "count": stats["indeterminado_count"]},
    ]

    vulnerable_assets = [
        {
            "asset": _stringify_for_html(r.get("Asset", "")),
            "final_url": _stringify_for_html(r.get("Final URL (after redirects)", "")),
            "detail": _stringify_for_html(r.get(CVE_COLUMN_NAME, "")),
        }
        for r in vulnerable_rows
    ]

    return {
        "summary": summary,
        "metrics": stats["metrics"],
        "cve_breakdown": cve_breakdown,
        "vulnerable_assets": vulnerable_assets,
    }


# Self-contained HTML template: inline CSS and JS, no external
# dependencies (no CDN or separate files), so it can be opened directly
# in the browser or sent without further requirements. The data payload
# (__SHEETS_JSON__) is substituted in write_html() with the real JSON.
#
# SECURITY: all content derived from the scan (asset names, HTTP headers,
# response fragments, etc.) can be influenced by the target being
# analyzed, so it is ALWAYS inserted into the DOM via
# textContent/createElement (see createText/cell below) and NEVER via
# innerHTML with string concatenation, to avoid stored XSS when this
# report is opened in a real browser.
_HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PHP/CMS reconnaissance report</title>
<style>
  :root {
    --header: #6B5B46;
    --header-light: #EFE3CC;
    --terracotta: #A8674A;
    --sage: #7A8C5D;
    --amber: #BE9A4D;
    --text: #3F362B;
    --muted: #8A7F6E;
    --border: #E0D3BA;
    --cream: #FAF6EF;
    --panel: #FFFCF5;
    --stripe: #F5EEE0;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    margin: 0; padding: 0; background: var(--cream); color: var(--text);
  }
  header {
    background: var(--header); color: #FFFCF5; padding: 16px 24px;
  }
  header h1 { margin: 0; font-size: 1.3em; }
  header p { margin: 4px 0 0; font-size: 0.85em; opacity: 0.85; }
  nav.tabs {
    display: flex; flex-wrap: wrap; gap: 4px; background: var(--panel);
    padding: 8px 16px 0; border-bottom: 2px solid var(--border);
    position: sticky; top: 0; z-index: 10;
  }
  nav.tabs button {
    border: none; background: var(--header-light); color: var(--header);
    padding: 10px 18px; border-radius: 8px 8px 0 0; cursor: pointer;
    font-size: 0.95em; font-weight: 600;
  }
  nav.tabs button.active { background: var(--header); color: #FFFCF5; }
  .toolbar {
    display: flex; gap: 10px; align-items: center;
    padding: 12px 16px; background: var(--panel); border-bottom: 1px solid var(--border);
  }
  .toolbar input[type="search"] {
    flex: 1; max-width: 420px; padding: 8px 12px; border: 1px solid var(--border);
    border-radius: 6px; font-size: 0.95em; background: #FFFFFB; color: var(--text);
  }
  .toolbar .counter { color: var(--muted); font-size: 0.85em; }
  main { padding: 16px; }
  .panel { display: none; }
  .panel.active { display: block; }
  table {
    width: 100%; border-collapse: collapse; background: var(--panel);
    box-shadow: 0 1px 3px rgba(107,91,70,0.12); font-size: 0.88em;
  }
  thead th {
    background: var(--header); color: #FFFCF5; text-align: left; padding: 10px 12px;
    cursor: pointer; user-select: none; white-space: nowrap;
  }
  thead th .arrow { opacity: 0.6; font-size: 0.8em; margin-left: 4px; }
  tbody td {
    padding: 8px 12px; border-bottom: 1px solid var(--border);
    vertical-align: top; white-space: pre-wrap; word-break: break-word;
    max-width: 420px;
  }
  tbody tr:nth-child(even) { background: var(--stripe); }
  tbody tr.hidden-row { display: none; }
  .empty { padding: 20px; color: var(--muted); font-style: italic; }
  .dash-grid { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }
  .card {
    background: var(--panel); border-radius: 8px; padding: 14px 18px; min-width: 220px;
    box-shadow: 0 1px 3px rgba(107,91,70,0.12);
  }
  .card .value { font-size: 1.8em; font-weight: 700; color: var(--header); }
  .card .label { color: var(--muted); font-size: 0.85em; }
  h2 { color: var(--header); font-size: 1.1em; margin: 24px 0 10px; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin: 8px 0; }
  .bar-row .name { width: 260px; font-size: 0.85em; }
  .bar-track { flex: 1; background: var(--stripe); border-radius: 4px; height: 14px; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--header); }
  .bar-row .pct { width: 80px; text-align: right; font-size: 0.85em; color: var(--muted); }
  .cve-vuln .bar-fill { background: var(--terracotta); }
  .cve-ok .bar-fill { background: var(--sage); }
  .cve-indet .bar-fill { background: var(--amber); }
  .table-vuln th { background: var(--terracotta); }
  .readme-disclaimer {
    background: #F6EEDA; border: 1px solid #D9C9A3; border-radius: 8px;
    padding: 14px 18px; margin-bottom: 18px; font-size: 0.95em; line-height: 1.5;
  }
  .table-readme td { white-space: normal; }
  .readme-note {
    margin-top: 14px; font-size: 0.85em; color: var(--muted); font-style: italic;
  }
</style>
</head>
<body>
<header>
  <h1>PHP/CMS reconnaissance report</h1>
  <p>Generated automatically — for use only in pentests or bug bounty programs with explicit authorization.</p>
</header>
<nav class="tabs" id="tabs"></nav>
<div class="toolbar">
  <input type="search" id="search" placeholder="Search in the active tab...">
  <span class="counter" id="counter"></span>
</div>
<main id="main"></main>

<script>
const SHEETS = __SHEETS_JSON__;
const TAB_ORDER = ["Readme", "Dashboard", "PHP Recon", "WP", "Drupal", "O365"];

let activeTab = TAB_ORDER[0];
// Sort state per tab: { "PHP Recon": {col: 2, asc: true}, ... }
const sortState = {};

function createText(value) {
  return document.createTextNode(value === null || value === undefined ? "" : String(value));
}

function cell(tag, text, extraClass) {
  const el = document.createElement(tag);
  if (extraClass) el.className = extraClass;
  el.appendChild(createText(text));
  return el;
}

// Table WITHOUT sorting or per-column filtering (unlike renderTable,
// meant for the scanned-data tabs): used for fixed listings like the
// "Priority" criteria on Readme or the Dashboard's vulnerable assets,
// which used to each build their own <thead>/<tbody> with the same loop
// repeated on its own.
// `makeCell(idx, value)` is optional, for special per-column styling
// (e.g. centering and highlighting the first column); by default it
// creates a plain-text <td> via cell().
function createStaticTable(extraClass, headers, rows, makeCell) {
  const table = document.createElement("table");
  if (extraClass) table.className = extraClass;

  const thead = document.createElement("thead");
  const trHead = document.createElement("tr");
  headers.forEach((h) => trHead.appendChild(cell("th", h)));
  thead.appendChild(trHead);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    row.forEach((value, idx) => {
      tr.appendChild(makeCell ? makeCell(idx, value) : cell("td", value));
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

function buildTabs() {
  const nav = document.getElementById("tabs");
  nav.innerHTML = "";
  TAB_ORDER.forEach((name) => {
    if (!SHEETS[name]) return;
    const btn = document.createElement("button");
    btn.appendChild(createText(name));
    if (name === activeTab) btn.className = "active";
    btn.addEventListener("click", () => {
      activeTab = name;
      document.getElementById("search").value = "";
      renderAll();
    });
    nav.appendChild(btn);
  });
}

function compareValues(a, b) {
  const na = parseFloat(a.replace(/[^0-9.\\-]/g, ""));
  const nb = parseFloat(b.replace(/[^0-9.\\-]/g, ""));
  const isNumA = a.trim() !== "" && !isNaN(na) && /^[\\s\\-\\+]*[0-9.,]+\\s*$/.test(a);
  const isNumB = b.trim() !== "" && !isNaN(nb) && /^[\\s\\-\\+]*[0-9.,]+\\s*$/.test(b);
  if (isNumA && isNumB) return na - nb;
  return a.localeCompare(b, "en", { sensitivity: "base" });
}

function renderTable(sheet, container) {
  const state = sortState[activeTab] || { col: null, asc: true };
  let rows = sheet.rows.slice();

  if (state.col !== null) {
    rows.sort((f1, f2) => {
      const r = compareValues(f1[state.col] || "", f2[state.col] || "");
      return state.asc ? r : -r;
    });
  }

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const trHead = document.createElement("tr");
  sheet.columns.forEach((col, idx) => {
    const th = document.createElement("th");
    th.appendChild(createText(col));
    if (state.col === idx) {
      const arrow = document.createElement("span");
      arrow.className = "arrow";
      arrow.appendChild(createText(state.asc ? "▲" : "▼"));
      th.appendChild(arrow);
    }
    th.addEventListener("click", () => {
      const prev = sortState[activeTab] || { col: null, asc: true };
      if (prev.col === idx) {
        sortState[activeTab] = { col: idx, asc: !prev.asc };
      } else {
        sortState[activeTab] = { col: idx, asc: true };
      }
      renderAll();
    });
    trHead.appendChild(th);
  });
  thead.appendChild(trHead);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  if (rows.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = sheet.columns.length;
    td.className = "empty";
    td.appendChild(createText(sheet.empty_message || "No data."));
    tr.appendChild(td);
    tbody.appendChild(tr);
  } else {
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      row.forEach((cellValue) => {
        const td = document.createElement("td");
        td.appendChild(createText(cellValue));
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

function renderReadme(sheet, container) {
  const d = sheet.data;

  const disclaimer = document.createElement("div");
  disclaimer.className = "readme-disclaimer";
  disclaimer.appendChild(createText(d.disclaimer));
  container.appendChild(disclaimer);

  container.appendChild(cell("h2", 'Criteria for the "Priority" column'));

  const criteriaRows = d.criteria.map((c) => [c.priority, c.criterion, c.description]);
  const table = createStaticTable("table-readme", ["Priority", "Criterion", "Description"], criteriaRows,
    (idx, value) => {
      const td = cell("td", value);
      if (idx === 0) {
        td.style.textAlign = "center";
        td.style.fontWeight = "700";
      }
      return td;
    });
  container.appendChild(table);

  const note = cell("p", d.note, "readme-note");
  container.appendChild(note);
}

function renderDashboard(sheet, container) {
  const d = sheet.data;

  const grid = document.createElement("div");
  grid.className = "dash-grid";
  d.summary.forEach((item) => {
    const card = document.createElement("div");
    card.className = "card";
    const value = document.createElement("div");
    value.className = "value";
    value.appendChild(createText(item.value));
    const label = document.createElement("div");
    label.className = "label";
    label.appendChild(createText(item.label));
    card.appendChild(value);
    card.appendChild(label);
    grid.appendChild(card);
  });
  container.appendChild(grid);

  container.appendChild(cell("h2", "Security metrics"));
  d.metrics.forEach((m) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    const name = cell("div", m.label + " (" + m.meet + "/" + m.total + ")", "name");
    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    fill.style.width = Math.max(0, Math.min(100, m.pct)) + "%";
    track.appendChild(fill);
    const pct = cell("div", m.pct + "%", "pct");
    row.appendChild(name);
    row.appendChild(track);
    row.appendChild(pct);
    container.appendChild(row);
  });

  container.appendChild(cell("h2", "CVE-2026-109618 / CVE-2026-109619 breakdown"));
  const totalCve = d.cve_breakdown.reduce((acc, c) => acc + c.count, 0) || 1;
  const cveClasses = ["cve-vuln", "cve-ok", "cve-indet"];
  d.cve_breakdown.forEach((c, idx) => {
    const row = document.createElement("div");
    row.className = "bar-row " + (cveClasses[idx] || "");
    const name = cell("div", c.label + " (" + c.count + ")", "name");
    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    const pct = Math.round((c.count / totalCve) * 1000) / 10;
    fill.style.width = Math.max(0, Math.min(100, pct)) + "%";
    track.appendChild(fill);
    const pctTxt = cell("div", pct + "%", "pct");
    row.appendChild(name);
    row.appendChild(track);
    row.appendChild(pctTxt);
    container.appendChild(row);
  });

  container.appendChild(cell("h2", "Assets vulnerable to CVE-2026-109618 / CVE-2026-109619 (mitigation priority)"));
  if (!d.vulnerable_assets || d.vulnerable_assets.length === 0) {
    const p = cell("p", "No vulnerable asset detected.", "empty");
    container.appendChild(p);
  } else {
    const vulnRows = d.vulnerable_assets.map((a) => [a.asset, a.final_url, a.detail]);
    const table = createStaticTable(
      "table-vuln", ["Asset", "Final URL (after redirects)", "Detail"], vulnRows,
    );
    container.appendChild(table);
  }
}

function applyFilter() {
  const q = document.getElementById("search").value.trim().toLowerCase();
  const panel = document.querySelector(".panel.active");
  if (!panel) return;
  const rows = panel.querySelectorAll("table:not(.table-vuln) tbody tr");
  let visible = 0;
  rows.forEach((tr) => {
    const text = tr.textContent.toLowerCase();
    const matches = q === "" || text.includes(q);
    tr.classList.toggle("hidden-row", !matches);
    if (matches) visible++;
  });
  const counter = document.getElementById("counter");
  if (rows.length > 0) {
    counter.textContent = visible + " / " + rows.length + " row(s)";
  } else {
    counter.textContent = "";
  }
}

function renderAll() {
  buildTabs();
  const main = document.getElementById("main");
  main.innerHTML = "";
  TAB_ORDER.forEach((name) => {
    const sheet = SHEETS[name];
    if (!sheet) return;
    const panel = document.createElement("div");
    panel.className = "panel" + (name === activeTab ? " active" : "");
    panel.dataset.sheet = name;
    if (sheet.type === "dashboard") {
      renderDashboard(sheet, panel);
    } else if (sheet.type === "readme") {
      renderReadme(sheet, panel);
    } else {
      renderTable(sheet, panel);
    }
    main.appendChild(panel);
  });
  applyFilter();
}

document.getElementById("search").addEventListener("input", applyFilter);
renderAll();
</script>
</body>
</html>
"""


def write_html(results: list, output_path: str):
    """
    Generates the HTML report equivalent to the Excel: same structure and
    tab order (Readme, Dashboard, PHP Recon, WP, Drupal, O365), built
    from _dataset_for_sheets (the same data used by write_excel, never a
    separately recomputed copy). The file is self-contained (inline
    CSS/JS, no CDN or additional files) so it can be opened directly in
    the browser or sent without further dependencies.
    """
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    data = _dataset_for_sheets(results)

    sheets_payload = {
        "Readme": {
            "type": "readme",
            "data": build_readme_html_data(),
        },
        "Dashboard": {
            "type": "dashboard",
            "data": build_dashboard_html_data(data["normal_rows"], data["sso_rows"]),
        },
        "PHP Recon": {
            "type": "table",
            "columns": data["columns"],
            "rows": _rows_as_lists(data["columns"], data["normal_rows"]),
            "empty_message": "No assets evaluated.",
        },
        "WP": {
            "type": "table",
            "columns": data["wp_columns"],
            "rows": _rows_as_lists(data["wp_columns"], data["wp_rows"]),
            "empty_message": "No asset with indications of WordPress (directories, files or version).",
        },
        "Drupal": {
            "type": "table",
            "columns": data["drupal_columns"],
            "rows": _rows_as_lists(data["drupal_columns"], data["drupal_rows"]),
            "empty_message": "No asset with indications of Drupal (headers, directories, files or version).",
        },
        "O365": {
            "type": "table",
            "columns": data["columns"],
            "rows": _rows_as_lists(data["columns"], data["sso_rows"]),
            "empty_message": "No asset redirected to a corporate (SSO) login.",
        },
    }

    # json.dumps already escapes quotes/backslashes correctly to embed
    # the result inside a <script>; the only case requiring an extra
    # manual escape is the literal substring "</script>" (if some
    # scanned value contained it, it would close the <script> block
    # early and break the page).
    json_payload = json.dumps(sheets_payload, ensure_ascii=False).replace("</script>", "<\\/script>")

    html_doc = _HTML_REPORT_TEMPLATE.replace("__SHEETS_JSON__", json_payload)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    if not os.path.isfile(output_path):
        print(f"[!] ERROR: the file {output_path} was not created correctly.", file=sys.stderr)
        return

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] HTML generated successfully: {output_path} ({size_kb:.1f} KB)", file=sys.stderr)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PHP version recon over a list of assets (authorized use)."
    )
    parser.add_argument("-i", "--input", required=True, help="File with one asset per line")
    parser.add_argument("--full", action="store_true", help="Include nikto and nuclei (slower)")
    parser.add_argument(
        "-t", "--threads", type=int, default=5,
        help=(
            "Different assets scanned IN PARALLEL (default: %(default)s). "
            "Increasing this value speeds up scanning a long list of "
            "assets, but does not affect the intrusiveness against a "
            "SINGLE host (see -pt/--path-threads)."
        ),
    )
    parser.add_argument(
        "-pt", "--path-threads", type=int, default=PER_ASSET_CONCURRENCY,
        help=(
            "Concurrent requests WITHIN each asset when checking default "
            "paths (WordPress, Drupal, generic PHP, favicon...). Not to "
            "be confused with -t/--threads, which parallelizes BETWEEN "
            "different assets. A higher value reduces the time per asset "
            "but increases intrusiveness (more simultaneous requests "
            "against the same host); use 1 for a fully sequential path "
            "scan, the most discreet/stealthy behavior. "
            "Default: %(default)s."
        ),
    )
    args = parser.parse_args()

    if args.threads < 1:
        print("[!] -t/--threads must be >= 1.", file=sys.stderr)
        sys.exit(1)
    if args.path_threads < 1:
        print("[!] -pt/--path-threads must be >= 1.", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not targets:
        print("[!] No assets found in the input file.", file=sys.stderr)
        sys.exit(1)

    print(
        f"[*] {len(targets)} assets loaded. Launching scan with {args.threads} "
        f"threads (--threads) x {args.path_threads} concurrent requests per "
        f"asset (--path-threads)...",
        file=sys.stderr,
    )

    # We normalize the assets the same way scan_target does (adds http://
    # if missing) so the results can be reordered exactly as in the input
    # file, even when they arrive out of order from the ThreadPoolExecutor.
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
        futures = {executor.submit(scan_target, t, args.full, args.path_threads): t for t in targets}
        for future in as_completed(futures):
            original_target = futures[future]
            try:
                res = future.result()
            except Exception as e:
                log(f"[!] Unexpected error scanning {original_target}: {e}")
                res = None

            completed += 1
            percent = (completed / total) * 100

            if res:
                results.append(res)
            else:
                failed.append(original_target)

            # Progress ONLY on the terminal (stderr): never written to the
            # Excel; the `res` dict that goes into the Excel is never
            # touched here.
            log(
                f"[progress] {completed}/{total} assets processed ({percent:5.1f}%) "
                f"- last: {original_target}"
            )

    results.sort(key=lambda r: order.get(r["Asset"], len(order)))

    if failed:
        print(f"[!] {len(failed)} asset(s) could not be processed: {failed}", file=sys.stderr)

    if not results:
        print("[!] No valid results were obtained. The Excel file is not generated.", file=sys.stderr)
        sys.exit(1)

    # Automatically generated file name (there's no more -o/--output):
    # "output_<timestamp of the moment the run finishes>", with extension
    # .xlsx for the Excel and .html for its equivalent report, so that
    # each run leaves its own files without overwriting those of a
    # previous run.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = f"output_{timestamp}"
    write_excel(results, f"{output_base}.xlsx")
    write_html(results, f"{output_base}.html")


if __name__ == "__main__":
    main()
