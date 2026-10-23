Teniendo en cuenta los CVE CVE-2026-109618 y CVE-2026-109619 de PHP, este es un script para que, teniendo en cuenta un listado de aplicaciones web (aka CMDB corporativa correspondiente), detecte si la aplicación usa PHP, si detecta la versión, y si es vulnerable a estos CVE (ya que también se han publicado las versiones afectadas). Creo que puede ayudar más establecer prioridades de mitigación en vez de buscar como loc@s PoCs con regalito. 

El script es modulable y detecta si la web usa ciertos CMS según rutas y ficheros por defecto, y según las tecnologías que haya en una organización se puede ampliar para que las detecte sin afectar (mucho) a lo que ya está implementado.

Y además, como nos gustan los colorinchis para compartirlo a nivel ejecutivo, el resultado es un excel con diferentes pestañas, y deja en una gráfica los números de webs que usan PHP y nº de las afectadas por los CVEs.

Es un escaneo activo (y muy ruidoso) de toda la vida del Señor, pero:
- Orientado a la vulnerabilidad que nos atañe,
- Nos permite tener una CMDB más actualizada desde una perspectiva externa (que desde dentro y sin bloqueos no es lo mismo, pero si lo ejecutas desde dentro también está bien para tener más/mejor/diferente visibilidad)
- Nos da una mejor visión de cómo exponen información las aplicaciones de una organización gracias a recursos por defecto que no siempre se restringen
- Tiene un mensaje de progreso para que no nos desesperemos mientras se ejecuta
- No tira de nada online, si lo ejecutas desde tu Kali/Parrot/Arch lo hace solito (mientras tengas python3 instalado)


Además, con esto nos da un orden de prioridades, ya que sabrás:
- Qué aplicaciones son vulnerables
- Qué aplicaciones usan PHP
- Qué aplicaciones usan CMS (de momento WordPress y Drupal, pero también escalable a otros más)
- Cómo se han identificado las versiones (rutas y ficheros por defecto, cabeceras HTTP, cookies, etc), por lo que también sabrás qué se tendría que corregir en la web para que otros no lo identifiquen ;)

Aviso también de que no está optimizado, para un listado de 500-600 aplicaciones tarda unas 3-4h en completarse, pero queda bonito, y es útil :)
