#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import glob
import time
import logging
from datetime import datetime
from urllib.parse import urlparse
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

pdfmetrics.registerFont(TTFont('SFPro', 'fonts/SFPro-Regular.ttf'))


logging.basicConfig(level=logging.INFO)

# Cargar variables de entorno desde el archivo .env
from dotenv import load_dotenv
load_dotenv()

# Configuración de las API Keys
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY")
if not VULNERS_API_KEY:
    logging.warning("No se encontró VULNERS_API_KEY en el entorno.")

from vulners import VulnersApi
vulners_api = VulnersApi(api_key=VULNERS_API_KEY)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    logging.warning("No se encontró OPENAI_API_KEY en el entorno.")

try:
    from openai import OpenAI
    
    client = OpenAI(api_key=OPENAI_API_KEY)
except ImportError:
    logging.error("El módulo openai no está instalado. Instálalo con 'pip install openai'.")


# --------------------------
# Función: obtener_recomendacion_chatgpt
# --------------------------
def obtener_recomendacion_chatgpt(texto):
    """
    Envía un prompt a la API de ChatGPT para que analice el texto dado y retorne un análisis,
    resumen y recomendaciones para mejorar la seguridad.
    """
    prompt = (
        f"Actúa como un experto en ciberseguridad. Analiza la siguiente información y proporciona un resumen "
        f"de las vulnerabilidades identificadas, explica sus implicaciones y ofrece recomendaciones detalladas "
        f"para mitigarlas:\n\n{texto}"
    )
    try:
        response = client.chat.completions.create(model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Eres un experto en ciberseguridad."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.7)
        return response.choices[0].message.content.strip()
    except Exception as e:
        logging.error(f"Error en obtener_recomendacion_chatgpt: {e}")
        return "No se pudo obtener un análisis automatizado. Consulta a un experto en ciberseguridad."


# --------------------------
# Función: escanear_puertos
# --------------------------
def escanear_puertos(host):
    """
    Ejecuta un escaneo de puertos con nmap en el host especificado y retorna la salida en texto.
    """
    try:
        result = subprocess.run(
            ["nmap", "-sV", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout if result.stdout else (result.stderr or "Sin salida de nmap.")
    except Exception as e:
        return f"Error en escanear_puertos: {e}"


# --------------------------
# Función: escanear_con_nikto
# --------------------------
def escanear_con_nikto(url):
    """
    Ejecuta la herramienta Nikto contra la URL proporcionada usando la opción "-h".
    Retorna la salida de Nikto en texto.
    """
    try:
        nikto_path = "/usr/local/bin/nikto"
        result = subprocess.run(
            [nikto_path, "-h", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ
        )
        salida = result.stdout.strip()
        return salida if salida else (result.stderr.strip() or "Sin salida de Nikto.")
    except Exception as e:
        return f"Error en escanear_con_nikto: {e}"


# --------------------------
# Función: escanear_con_wapiti
# --------------------------
def escanear_con_wapiti(url):
    """
    Ejecuta Wapiti contra la URL dada en formato JSON.
    Elimina archivos JSON previos, ejecuta Wapiti y espera a que se genere el reporte.
    Luego, usando el hostname de la URL, busca el archivo JSON generado y retorna su contenido.
    """
    try:
        # Eliminar archivos JSON previos en el directorio actual
        for f in glob.glob("*.json"):
            os.remove(f)

        # Ejecutar Wapiti; el reporte se guarda en un archivo en el directorio actual
        subprocess.run(
            ["wapiti", "-u", url, "-f", "json", "--max-links-per-page", "10"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Esperar a que el archivo JSON se genere (ajustar el sleep si es necesario)
        time.sleep(2)

        # Extraer el hostname de la URL para construir el patrón de búsqueda
        parsed = urlparse(url)
        hostname = parsed.hostname  # Ejemplo: "82.98.175.101"
        pattern = f"*{hostname}*.json"
        files = glob.glob(pattern)
        if files:
            # Seleccionar el archivo JSON más reciente
            file_path = max(files, key=os.path.getmtime)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return content
        else:
            return "No se encontró el archivo JSON generado por Wapiti."
    except Exception as e:
        return f"Error en escanear_con_wapiti: {e}"


# --------------------------
# Función: generar_reporte
# --------------------------
def generar_reporte(target, nmap_result, nikto_result, wapiti_result):
    """
    Genera un informe PDF con estilo iOS/Apple usando ReportLab que incluye:
      - Resultados de nmap, Nikto y Wapiti.
      - Análisis y recomendaciones (generadas por ChatGPT) para cada sección, presentadas en "cards".
      - Una barra de puntaje que indica el estado general de seguridad.
    El PDF se guarda en el directorio actual con un nombre basado en el target.
    """
    import re
    import html
    import textwrap
    from datetime import datetime
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, 
                                    Table, TableStyle, PageBreak)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics

    # Registrar la fuente SF Pro (usa el mismo archivo si no tienes la versión semibold)
    pdfmetrics.registerFont(TTFont('SFPro', 'fonts/SFPro-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('SFPro-Bold', 'fonts/SFPro-Regular.ttf'))

    def format_text(text):
        """Escapa HTML y reemplaza saltos de línea."""
        return html.escape(text).replace("\n", "<br/>")

    # ---------------------------------------------------------
    # Función auxiliar para crear una "card" con texto envuelto
    # ---------------------------------------------------------
    from reportlab.platypus import Table, TableStyle
    def crear_card_texto(texto, style, width=520, bg_color=colors.HexColor("#F0F0F0")):
        """
        Divide 'texto' en líneas usando textwrap, y cada línea se convierte en una fila.
        Se retorna un flowable Table con splitByRow=1 para que se pueda partir entre páginas.
        """
        wrapped_lines = textwrap.wrap(texto, width=100)  # Ajusta 'width=100' según tu necesidad
        filas = []
        for line in wrapped_lines:
            p = Paragraph(line, style)
            filas.append([p])
        table = Table(filas, colWidths=[width], splitByRow=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_color),
            ('BOX', (0,0), (-1,-1), 1, colors.lightgrey),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        return table

    # ------------------------------
    # Cálculo de puntaje Nikto
    # ------------------------------
    total_vuln = 0
    match = re.search(r"and (\d+) item\(s\)", nikto_result)
    if match:
        total_vuln = int(match.group(1))
    if total_vuln == 0:
        puntaje = 1
    elif total_vuln < 5:
        puntaje = 3
    elif total_vuln < 10:
        puntaje = 5
    elif total_vuln < 15:
        puntaje = 7
    else:
        puntaje = 10

    puntaje_desc = {
        1: ("Excelente: El sistema está seguro. \u2705", colors.green),           
        3: ("Bueno: Requiere mejoras menores. \U0001F340", colors.lawngreen),     
        5: ("Moderado: Se recomienda reforzar la seguridad. \u26A0\uFE0F", colors.yellow),
        7: ("Alto: Se necesitan medidas urgentes. \U0001F6D1", colors.orange),   
        10:("Crítico: Vulnerabilidades graves detectadas. \U0001F6A8", colors.red)
    }
    estado_text, estado_color = puntaje_desc[puntaje]

    # ------------------------------
    # Configurar estilos
    # ------------------------------
    base_styles = getSampleStyleSheet()
    styles = {
        "TitleApple": ParagraphStyle(
            name='TitleApple',
            fontName='SFPro-Bold',
            fontSize=18,
            textColor=colors.black,
            leading=24,
            spaceAfter=12
        ),
        "HeadingApple": ParagraphStyle(
            name='HeadingApple',
            fontName='SFPro-Bold',
            fontSize=14,
            textColor=colors.black,
            leading=18,
            spaceAfter=8
        ),
        "BodyApple": ParagraphStyle(
            name='BodyApple',
            fontName='SFPro',
            fontSize=11,
            textColor=colors.black,
            leading=14,
            spaceAfter=6
        )
    }

    # ------------------------------
    # Crear el documento
    # ------------------------------
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    pdf_filename = f"reporte_{safe_target}.pdf"
    doc = SimpleDocTemplate(
        pdf_filename, 
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=28
    )

    Story = []

    # ===== Título Principal =====
    from reportlab.platypus import Spacer, Paragraph
    Story.append(Paragraph("\U0001F4DD Reporte de Escaneo de Vulnerabilidades", styles["TitleApple"]))
    Story.append(Spacer(1, 12))

    # ===== Info General =====
    fecha_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    info_text = (f"\\U0001F517 <b>Objetivo:</b> {target}"
                 f"<br/>\\U0001F4C5 <b>Fecha:</b> {fecha_str}")
    info_text = info_text.replace("\\U0001F517", "\U0001F517").replace("\\U0001F4C5", "\U0001F4C5")
    Story.append(Paragraph(info_text, styles["BodyApple"]))
    Story.append(Spacer(1, 16))

    # ===== Puntaje Vulnerabilidades =====
    from reportlab.platypus import Table, TableStyle
    Story.append(Paragraph("\U0001F512 Estado General de Seguridad:", styles["HeadingApple"]))
    score_data = [[estado_text]]
    score_table = Table(score_data, colWidths=[doc.width])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), estado_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12)
    ]))
    Story.append(score_table)
    Story.append(Spacer(1, 16))

    # ===== Sección nmap =====
    Story.append(Paragraph("\U0001F4E1 Resultados de Escaneo de Puertos (nmap):", styles["HeadingApple"]))
    Story.append(Paragraph(format_text(nmap_result), styles["BodyApple"]))
    Story.append(Spacer(1, 12))

    prompt_nmap = f"Analiza la siguiente salida de nmap y proporciona recomendaciones para mejorar la seguridad:\n{nmap_result}"
    analisis_nmap = obtener_recomendacion_chatgpt(prompt_nmap)
    Story.append(Paragraph("\U0001F916 Análisis de nmap:", styles["HeadingApple"]))
    # Crear "card" con textwrap
    nmap_card = crear_card_texto(analisis_nmap, styles["BodyApple"], width=doc.width)
    Story.append(nmap_card)
    Story.append(Spacer(1, 16))

    # ===== Sección Nikto =====
    Story.append(Paragraph("\U0001F50D Resultados de Nikto:", styles["HeadingApple"]))
    Story.append(Paragraph(format_text(nikto_result), styles["BodyApple"]))
    Story.append(Spacer(1, 12))

    prompt_nikto = f"Analiza la siguiente salida de Nikto, identifica vulnerabilidades y ofrece recomendaciones:\n{nikto_result}"
    analisis_nikto = obtener_recomendacion_chatgpt(prompt_nikto)
    Story.append(Paragraph("\U0001F916 Análisis de Nikto:", styles["HeadingApple"]))
    nikto_card = crear_card_texto(analisis_nikto, styles["BodyApple"], width=doc.width)
    Story.append(nikto_card)
    Story.append(Spacer(1, 16))

    # ===== Sección Wapiti =====
    Story.append(Paragraph("\U0001F575 Resultados de Wapiti (JSON):", styles["HeadingApple"]))
    Story.append(Paragraph(format_text(wapiti_result), styles["BodyApple"]))
    Story.append(Spacer(1, 12))

    prompt_wapiti = f"Interpreta el siguiente informe JSON generado por Wapiti, resume las vulnerabilidades y ofrece recomendaciones:\n{wapiti_result}"
    analisis_wapiti = obtener_recomendacion_chatgpt(prompt_wapiti)
    Story.append(Paragraph("\U0001F916 Análisis de Wapiti:", styles["HeadingApple"]))
    wapiti_card = crear_card_texto(analisis_wapiti, styles["BodyApple"], width=doc.width)
    Story.append(wapiti_card)
    Story.append(Spacer(1, 16))

    # ===== Sección: Resumen Global =====
    Story.append(Paragraph("\U0001F5D2 Resumen y Recomendaciones Globales:", styles["HeadingApple"]))
    resumen_text = (
        "Este es un resumen global del escaneo que integra los hallazgos de nmap, Nikto y Wapiti.\n\n"
        "Resultados de nmap:\n" + nmap_result + "\n\n"
        "Resultados de Nikto:\n" + nikto_result + "\n\n"
        "Resultados de Wapiti:\n" + wapiti_result
    )
    prompt_resumen = (
        "Analiza el siguiente resumen de resultados, identifica las principales vulnerabilidades "
        "y ofrece recomendaciones generales para mejorar la seguridad:\n" + resumen_text
    )
    analisis_resumen = obtener_recomendacion_chatgpt(prompt_resumen)
    resumen_card = crear_card_texto(analisis_resumen, styles["BodyApple"], width=doc.width)
    Story.append(resumen_card)
    Story.append(Spacer(1, 16))

    # Construir el PDF
    try:
        doc.build(Story)
        print(f"Reporte generado: {pdf_filename}")
    except Exception as e:
        print(f"Error al generar el PDF: {e}")



