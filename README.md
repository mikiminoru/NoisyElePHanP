# php_version_recon.py

A reconnaissance script that fingerprints the PHP version (and, where applicable, the WordPress/Drupal footprint) of a list of web assets, and produces a ready-to-read **Excel workbook** and an equivalent self-contained **HTML report**.

> ⚠️ **Authorized use only.** This tool is intended exclusively for penetration tests or bug bounty programs where you have **explicit authorization** to test the listed assets. Running it against targets you are not authorized to test may be illegal. The generated reports carry this same disclaimer on their "Readme" tab.

## What it does

Given a plain-text list of URLs, the script runs each asset through a battery of lightweight, low-noise fingerprinting checks and compiles the results into one row per asset:

- **HTTP headers & cookies** — `X-Powered-By`/`Server` headers, PHP session cookie signatures.
- **Default/exposed PHP artifacts** — `phpinfo.php`, PHP error logs, `composer.json`/`composer.lock`, default PHP directories.
- **CVE correlation** — when a specific PHP version can be extracted, it is checked against known PHP CVEs (CVE-2026-109618 / CVE-2026-109619) to flag whether the asset is running a vulnerable, end-of-life, or unpatched branch.
- **CMS fingerprinting** — dedicated WordPress and Drupal detection (default paths/files, version markers in `readme.html`/`CHANGELOG.txt`, CMS-specific headers and cookies), with confidence levels (weak/strong) and automatic reconciliation when both CMS signals appear together.
- **External tool integration (optional)** — if available on `PATH`, it also shells out to `nmap` (`http-php-version` script), `whatweb`, and, with `--full`, `nikto` and `nuclei`.
- **SSO/IdP detection** — assets that redirect to a corporate identity provider (e.g. `login.microsoftonline.com`) are set aside into their own tab instead of being evaluated as regular web apps.

Every asset is also assigned a **priority level** (1 = confirmed CVE-vulnerable, 2 = generic PHP usage with no CMS identified, 3 = WordPress/Drupal identified, 4 = no PHP/CMS evidence found) to help triage a long list of targets at a glance.

## Output

Each run produces two files named with the scan's timestamp, so repeated runs never overwrite each other:

```
output_<YYYYMMDD>_<HHMMSS>.xlsx
output_<YYYYMMDD>_<HHMMSS>.html
```

Both share the exact same underlying data and are organized into the same tabs:

| Tab | Content |
|---|---|
| **Readme** | Scope/authorization disclaimer and a description of the priority criteria |
| **Dashboard** | Summary counters and charts (vulnerable vs. safe vs. indeterminate, CMS breakdown) |
| **PHP Recon** | The full, unfiltered table — every scanned asset, one row each |
| **WP** | Only assets with actual WordPress evidence (paths, files, or version found) |
| **Drupal** | Only assets with actual Drupal evidence (paths, files, headers/cookies, or version found) |
| **O365** | Assets that redirected to a corporate SSO/IdP and were skipped |

The HTML report is a single self-contained file (no external dependencies) with a tabbed interface, so it can be opened directly in a browser or shared as-is.

## Requirements

```bash
pip install requests openpyxl
```

Optional, used automatically if found on `PATH` (otherwise the corresponding column is filled with `N/A - tool not found`):

- `nmap`
- `whatweb`
- `nikto` (only with `--full`)
- `nuclei` (only with `--full`)

## Usage

```bash
python3 php_version_recon.py -i assets.txt
python3 php_version_recon.py -i assets.txt --full
```

Input file: one asset (URL) per line.

```
https://example1.com
https://example2.com
http://192.168.1.10:8080
```

### Options

| Flag | Description |
|---|---|
| `-i, --input` | File with one asset per line **(required)** |
| `--full` | Also run `nikto` and `nuclei` (slower, more intrusive) |
| `-t, --threads` | Number of assets scanned **in parallel** (default: 5) |
| `-pt, --path-threads` | Concurrent requests **within a single asset** when probing default paths (default: 6). Use `1` for fully sequential, stealthier scanning |

`--threads` controls how many *different* assets are scanned at once; `--path-threads` controls how aggressively a *single* asset is probed. Tune the latter down when operating against sensitive or rate-limited targets.

## Disclaimer

This project is provided for authorized security testing and educational purposes only. The author assumes no liability for misuse. Always obtain written authorization before scanning any system you do not own.
