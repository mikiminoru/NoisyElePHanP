Script de reconocimiento para identificar la version de PHP usada por una lista de aplicaciones web, pensado UNICAMENTE para uso en pentests o programas de bug bounty con autorizacion explicita sobre los activos.
 
Lee un fichero de texto con un activo (URL) por linea, lanza varias tecnicas de fingerprinting contra cada uno y vuelca los resultados en un Excel: una fila por activo, una columna por tecnica/herramienta.
 
Requisitos:
    pip install requests openpyxl
 
Herramientas externas opcionales (si estan instaladas en el PATH, se usan；si no, esa columna se rellena con "N/A - herramienta no encontrada"):
    - nmap (script http-php-version)
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
