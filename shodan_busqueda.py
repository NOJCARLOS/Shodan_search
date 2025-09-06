#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de consola para consultar Shodan dirigido a Guatemala (country:GT).

Características principales:
- Construye la consulta forzando el filtro country:GT y permite acotar por ciudad.
- Permite añadir filtros adicionales de Shodan (p. ej., port:80, product:"Apache"),
  excluyendo explícitamente el uso de org: según el requisito.
- Recorre los resultados paginando el endpoint oficial de Shodan Host Search.
- Muestra todos los resultados encontrados en una tabla legible por consola.
- Presenta un resumen con:
    * Total de direcciones IP únicas.
    * Total de IPs por puerto abierto.


Requisitos:
- Python 3.8 o superior.
- Paquete requests:  pip install requests

Endpoint empleado: 
- https://api.shodan.io/shodan/host/search?key=API_KEY&query=QUERY&facets=FACETS&page=N
"""

from __future__ import annotations

import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from urllib.parse import urlencode, quote_plus

import requests


# ========================
# Configuración del alumno
# ========================
STUDENT = {
    "carnet":  "1990-15-16083",
    "nombre":  "Carlos Enrique Noj Pajarito",
    "curso":   "Seguridad y Auditoría de Sistemas",
    "seccion": "B",
}

# =============================
# Configuración de Shodan / API
# =============================
# API Key proporcionada por el usuario (quemada en el código)
SHODAN_API_KEY: str = "XXXXXXX"

# Filtro de ciudad (ajustable). Dejar como None para no forzar ciudad concreta.
CITY_FILTER: Optional[str] = None

# Filtros adicionales de Shodan para la consulta (NO usar "org:").
# Ejemplos válidos: 'port:80', 'product:"Apache"', 'title:"Remote Desktop"'
ADDITIONAL_FILTERS: str = ""

# Facetas opcionales (para estadísticos rápidos de Shodan). Dejar en "" para omitir.
# Ejemplo: 'port:20,product:10,city:15'
FACETS: str = ""

# Límite de resultados a descargar (con paginado).
MAX_RESULTS: int = 1000

# Pausa entre páginas para evitar límites de la API (segundos).
SLEEP_SECONDS: float = 1.0

# Palabras clave prohibidas en la consulta (según requisito).
PROHIBITED_KEYWORDS = ["org:"]


def build_query() -> str:
    """
    Construye la cadena de búsqueda final para Shodan.
    Se fuerza el país Guatemala mediante country:GT y se integra el filtro de
    ciudad si está configurado. Luego, se anexan filtros adicionales siempre
    que no contengan palabras prohibidas.
    """
    base = 'country:GT'
    if CITY_FILTER:
        base += f' city:"{CITY_FILTER}"'

    if ADDITIONAL_FILTERS:
        low = ADDITIONAL_FILTERS.lower()
        if any(x in low for x in PROHIBITED_KEYWORDS):
            raise SystemExit("ERROR: El uso de filtros por organización (org:) está prohibido por los requisitos.")
        base = f"{base} {ADDITIONAL_FILTERS}"
    return base.strip()


def http_get_shodan(query: str, page: int, facets: str = "") -> dict:
    """
    Realiza una solicitud HTTP GET al endpoint de Shodan Host Search.
    Acepta la consulta (query), el número de página y las facetas opcionales.
    Devuelve el JSON de respuesta como diccionario. Usa exactamente la plantilla:
    https://api.shodan.io/shodan/host/search?key=API_KEY&query=QUERY&facets=FACETS&page=N
    """
    params = {
        "key": SHODAN_API_KEY,
        "query": query,
        "page": page,
    }
    if facets:
        params["facets"] = facets

    url = "https://api.shodan.io/shodan/host/search"
    # Se usa urlencode con quote_plus para conservar espacios en filtros complejos
    full_url = f"{url}?{urlencode(params, quote_via=quote_plus)}"

    resp = requests.get(full_url, timeout=60)
    if resp.status_code != 200:
        body = resp.text
        raise SystemExit(
            f"ERROR HTTP {resp.status_code} al consultar Shodan.\n"
            f"URL: {full_url}\n"
            f"Cuerpo: {body}"
        )
    return resp.json()


def fetch_all(query: str, facets: str, max_results: int, sleep_s: float):
    """
    Descarga resultados de Shodan en varias páginas hasta alcanzar el límite
    deseado o agotar resultados. Devuelve:
      - matches: lista de resultados consolidada y sin duplicados (por ip,puerto).
      - total_reported: total de resultados informados por Shodan para la consulta.
      - facets_obj: objeto con facetas (si se solicitaron en la primera página).
    """
    matches: List[dict] = []
    seen: Set[Tuple[str, int]] = set()
    page = 1
    facets_obj: Optional[dict] = None

    first = http_get_shodan(query, page=page, facets=facets)
    total_reported = int(first.get("total", 0))
    if first.get("facets"):
        facets_obj = first["facets"]

    def add_batch(batch: List[dict]) -> int:
        added = 0
        for m in (batch or []):
            ip = m.get("ip_str") or m.get("ip")
            port = m.get("port")
            key = (str(ip), int(port) if port is not None else -1)
            if key not in seen:
                seen.add(key)
                matches.append(m)
                added += 1
        return added

    add_batch(first.get("matches", []))

    while len(matches) < max_results and len(matches) < total_reported:
        page += 1
        try:
            data = http_get_shodan(query, page=page)
        except SystemExit as exc:
            print(f"ADVERTENCIA: No fue posible continuar en la página {page}: {exc}", file=sys.stderr)
            break

        batch = data.get("matches", [])
        if not batch:
            break

        added = add_batch(batch)
        if added == 0:
            break
        time.sleep(sleep_s)

    return matches[:max_results], total_reported, facets_obj


def normalize(value) -> str:
    """
    Convierte valores potencialmente None o listas a una representación de texto segura.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value if v is not None)
    return str(value)


def print_banner(student: Dict[str, str], final_query: str) -> None:
    """
    Imprime la cabecera con datos del estudiante y la consulta efectiva.
    """
    line = "=" * 90
    print(line)
    print("BÚSQUEDA SHODAN EN GUATEMALA".center(90))
    print(line)
    print(f"Fecha/Hora: {datetime.now().isoformat(timespec='seconds')}")
    print(f"Consulta (forzada a Guatemala): {final_query}")
    print("-" * 90)
    print("DATOS DEL ESTUDIANTE".center(90))
    print(f"Carnet  : {student['carnet']}")
    print(f"Nombre  : {student['nombre']}")
    print(f"Curso   : {student['curso']}")
    print(f"Sección : {student['seccion']}")
    print(line)
    print()


def print_facets(facets_obj: Optional[dict]) -> None:
    """
    Muestra, si existen, las facetas devueltas por Shodan (Top-N por categoría).
    """
    if not facets_obj:
        return
    print("FACETS (Top-N por categoría)")
    print("-" * 90)
    for facet_name, items in facets_obj.items():
        if not items:
            continue
        print(f"* {facet_name}:")
        for it in items:
            val = normalize(it.get("value"))
            cnt = normalize(it.get("count"))
            print(f"    {val:<30} {cnt:>6}")
    print()


def print_results(results: List[dict]) -> None:
    """
    Muestra una tabla con los resultados descargados. Las columnas incluyen:
    IP, Puerto, Protocolo, Producto, Hostnames, Ciudad, Org, Fecha.
    """
    if not results:
        print("No se encontraron resultados para la consulta.")
        return

    header = f"{'IP':<18} {'Puerto':<7} {'Proto':<6} {'Producto':<22} {'Hostnames':<30} {'Ciudad':<16} {'Org':<18} {'Fecha':<20}"
    print(header)
    print("-" * len(header))
    for m in results:
        ip = normalize(m.get("ip_str") or m.get("ip"))
        port = normalize(m.get("port"))
        proto = normalize(m.get("transport"))
        product = normalize(m.get("product") or (m.get("_shodan") or {}).get("module"))
        hostnames = normalize(m.get("hostnames"))[:29]
        city = normalize((m.get("location") or {}).get("city"))[:15]
        org = normalize(m.get("org"))[:17]
        ts = normalize(m.get("timestamp"))[:19]

        line = f"{ip:<18} {port:<7} {proto:<6} {product[:21]:<22} {hostnames:<30} {city:<16} {org:<18} {ts:<20}"
        print(line)
    print()


def print_summary(results: List[dict], student: Dict[str, str]) -> None:
    """
    Calcula e imprime el resumen solicitado: total de IPs únicas y total de IPs por puerto.
    También imprime nuevamente los datos del estudiante al final.
    """
    unique_ips: Set[str] = set()
    port_to_ips: Dict[int, Set[str]] = {}

    for m in results:
        ip = m.get("ip_str") or m.get("ip")
        if ip:
            unique_ips.add(str(ip))
        port = m.get("port")
        if port is not None:
            try:
                p = int(port)
                port_to_ips.setdefault(p, set()).add(str(ip))
            except Exception:
                pass

    line = "=" * 90
    print(line)
    print("RESUMEN".center(90))
    print(line)
    print(f"Total de direcciones IP identificadas: {len(unique_ips)}")
    print()
    print("Total de IPs por puerto abierto:")
    if not port_to_ips:
        print("  (sin puertos identificados)")
    else:
        for p, ips in sorted(port_to_ips.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"  - Puerto {p:<5} -> {len(ips)} IP(s)")
    print()
    print("DATOS DEL ESTUDIANTE")
    print(f"Carnet  : {student['carnet']}")
    print(f"Nombre  : {student['nombre']}")
    print(f"Curso   : {student['curso']}")
    print(f"Sección : {student['seccion']}")
    print(line)


def main() -> None:
    """
    Orquesta la ejecución completa:
      1) Construcción de la consulta para Guatemala.
      2) Descarga de resultados con paginado.
      3) Impresión de cabecera, facetas (si hay), resultados y resumen.
    """
    final_query = build_query()
    print_banner(STUDENT, final_query)

    results, total_reported, facets_obj = fetch_all(
        query=final_query,
        facets=FACETS,
        max_results=MAX_RESULTS,
        sleep_s=SLEEP_SECONDS,
    )

    print(f"Total reportado por Shodan: {total_reported}")
    print(f"Total descargado en esta ejecución: {len(results)}\n")

    print_facets(facets_obj)
    print_results(results)
    print_summary(results, STUDENT)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nEjecución interrumpida por el usuario.", file=sys.stderr)
        sys.exit(130)
