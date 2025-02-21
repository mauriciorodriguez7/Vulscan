#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules import escanear_puertos, escanear_con_nikto, escanear_con_wapiti, generar_reporte
from urllib.parse import urlparse
from tqdm import tqdm  # Para la barra de progreso

def menu_principal():
    print("=== Menú Principal ===")
    print("1. Escaneo de red (nmap)")
    print("2. Escaneo de una página web (Nikto y Wapiti)")
    print("3. Salir")
    opcion = input("Seleccione una opción: ").strip()

    if opcion == "1":
        host = input("Ingrese la IP/host a escanear: ").strip()
        # Solo 1 tarea principal (nmap)
        with tqdm(total=1, desc="Progreso del escaneo", unit="tarea") as pbar:
            nmap_result = escanear_puertos(host)
            pbar.update(1)  # Actualizamos la barra a 100%
        
        # Generar el reporte (sin Nikto ni Wapiti)
        generar_reporte(host, nmap_result, "No se ejecutó Nikto", "No se ejecutó Wapiti")

    elif opcion == "2":
        url = input("Ingrese la URL a analizar: ").strip()
        parsed = urlparse(url)
        host = parsed.hostname  # para nmap

        # En este caso tenemos 4 tareas: nmap, nikto, wapiti y la generación del reporte
        with tqdm(total=4, desc="Progreso del escaneo", unit="tarea") as pbar:
            # 1) nmap
            nmap_result = escanear_puertos(host)
            pbar.update(1)

            # 2) nikto
            nikto_result = escanear_con_nikto(url)
            pbar.update(1)

            # 3) wapiti
            wapiti_result = escanear_con_wapiti(url)
            pbar.update(1)

            # 4) Generar reporte PDF
            generar_reporte(url, nmap_result, nikto_result, wapiti_result)
            pbar.update(1)

    elif opcion == "3":
        print("Saliendo...")
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    menu_principal()
