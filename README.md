
# SYNAPSE Framework REDTEAM - El Pentester Aumentado por IA

> **Visión**: Crear un sistema que emule el ciclo de pensamiento de un pentester humano, siguiendo el famoso bucle **OODA** (Observar, Orientar, Decidir, Actuar), pero potenciado por inteligencia artificial.

---

# El Bucle OODA + IA

### Observar (Scan)
El framework escanea la red para recopilar datos en bruto.  
*Módulo implementado.*

### 🧭 Orientar (Intel)
La IA analiza los datos, genera un mapa mental en ASCII art, identifica vulnerabilidades potenciales y comprende el "campo de batalla".  
*Módulo mejorado.*

###  Decidir (IA Interactiva)
La IA propone acciones en lenguaje comprensible para la máquina.  
Ejemplo:  
> “He encontrado un servidor web. Mi recomendación es ejecutar un escaneo de vulnerabilidades web.”

*La gran mejora.*

### 🛠️ Actuar (Exploit, Pivot, Agent)
El framework ejecuta las acciones decididas por la IA (o aprobadas por el usuario):  
- Lanzar scripts  
- Establecer túneles  
- Buscar más información


## ¿Por Qué SYNAPSE?
En el campo de batalla moderno, la velocidad y la inteligencia lo son todo. SYNAPSE fue creado para resolver los cuellos de botella de las operaciones de Red Team:
- Sobrecarga Cognitiva: Demasiados datos, muy poco tiempo para analizarlos.
- Acciones Repetitivas: Escaneos, enumeración y ataques básicos que consumen un tiempo valioso.
- Brecha de Habilidades: Centraliza tácticas avanzadas en una interfaz simple e interactiva.

SYNAPSE aborda esto con un núcleo de IA colaborativa. No solo ejecuta tus órdenes; analiza los resultados, entiende el contexto de la misión y te propone el siguiente movimiento táctico. Es un miembro más de tu equipo.

## Características de Élite
- Cerebro de Misión Persistente: Cada operación se gestiona como una "misión", con un estado (state.json) que actúa como la memoria a largo plazo de la IA.
- Co-Piloto de IA Interactivo: Entra en un chat de misión y colabora con la IA. Pídele resúmenes, proponle estrategias y autoriza sus recomendaciones de ataque con un simple "sí".
- Modo Autónomo: Desata a SYNAPSE con el comando mission autonomous y observa cómo ejecuta un pentest básico por sí solo, escaneando, analizando y actuando en un bucle OODA.
- Arsenal Extensible: Un sistema de plugins te permite integrar tus propios scripts y herramientas, enseñándole a la IA nuevas "habilidades".
- Movimiento Lateral Avanzado: Va más allá del simple reenvío de puertos con un proxy SOCKS5 integrado, convirtiendo cualquier activo comprometido en un portal a la red interna.
- Agente de C2 Sigiloso: Despliega el agente en un objetivo y contrólalo remotamente a través de una API HTTPS segura, con certificados generados en memoria para una operación sin ficheros.
- Capacidades Multi-dominio: Equipado con módulos para pentesting de Cloud (AWS) y Kubernetes, además de redes tradicionales.

# Manual de Operaciones
## Fase 1: Reconocimiento y Planificación de la Misión
Toda operación comienza con un plan.

1. Iniciar la Misión:
Crea un espacio de trabajo para la operación. Esto genera un directorio y un state.json que será la memoria de la IA.
```Bash
scaner-pro mission start "Operacion_Quimera"

```
Lanzar el Escaneo Inicial:
Alimenta a la IA con los primeros datos. Usa el flag -m para guardar los resultados en el contexto de la misión.
code
```Bash
scaner-pro scan 10.10.20.0/24 22,80,443,445,3389,8080 -m "Operacion_Quimera"
```Entrar en la Sala de Operaciones (Chat):
Aquí es donde colaboras con tu co-piloto.
```Bash
scaner-pro mission chat "Operacion_Quimera"
```
Dentro del chat, puedes preguntar:
resume los hallazgos.
¿cuál es el host más interesante?
propón un plan de ataque para 10.10.20.55.
Fase 2: Infiltración y Explotación
La IA te propondrá acciones. Si las autorizas, SYNAPSE las ejecutará.
Ejemplo de Interacción (Fuzzing):
[SYNAPSE]: He encontrado un servidor web en http://10.10.20.55:8080. Recomiendo un escaneo de directorios para encontrar un panel de administración.
[PRÓXIMA ACCIÓN RECOMENDADA]: fuzz web-dir -u http://10.10.20.55:8080 -w ./wordlists/common.txt
¿Proceder? (s/n) > s
Ejemplo de Interacción (Fuerza Bruta):
[SYNAPSE]: El escaneo ha revelado un puerto SSH en 10.10.20.70. El siguiente paso lógico es intentar un ataque de fuerza bruta con credenciales comunes.
[PRÓXIMA ACCIÓN RECOMENDADA]: bruteforce ssh -t 10.10.20.70 -U ./wordlists/users.txt -P ./wordlists/passwords.txt
¿Proceder? (s/n) > s
Fase 3: Post-Explotación y Movimiento Lateral
Una vez dentro, el objetivo es expandir tu control.
Caza de Botín (Looting):
Despliega el agente en el objetivo y ordénale que busque secretos.
code
```Bash
# Comando enviado a través del agente C2
{
  "comando": "loot",
  "args": ["hunt", "-p", "/home", "-m", "Operacion_Quimera"]
}
```

La IA analizará los resultados:
[SYNAPSE]: ¡Botín encontrado! Se ha localizado una clave privada SSH en /home/dev/.ssh/id_rsa. Recomiendo usar esta clave para intentar pivotar al host 10.10.20.90, que estaba en la misma subred.
Pivoting con Proxy SOCKS (El Portal):
Esta es la técnica definitiva para dominar la red interna.
Activa el proxy en la máquina comprometida (a través del agente C2):

```Json
{
  "comando": "pivot",
  "args": ["socks", "-p", "9050"]
}
```

En tu máquina de ataque, configura proxychains (o FoxyProxy en tu navegador) para usar socks5 10.10.20.70 9050.
Ahora, ataca la red interna como si estuvieras dentro:

```Bash
proxychains nmap -sT -p- 10.10.30.0/24
proxychains curl http://intranet.corp.local
```
Fase 4: Operaciones Autónomas y Persistencia
Para operaciones a largo plazo o cuando necesitas maximizar la eficiencia.
Modo Autónomo:
Después de un escaneo inicial, puedes desatar a la IA.

```Bash
scaner-pro mission autonomous "Operacion_Quimera" -t 5m
```
SYNAPSE trabajará por sí solo, ejecutando escaneos, fuzzing y otras técnicas de reconocimiento en un bucle, guardando cada hallazgo y profundizando en la red. Te alertará si encuentra una brecha crítica.
Establecer Persistencia:
Una vez que tienes acceso a una máquina importante, asegúrate de que sobreviva a un reinicio.
code
```Bash
# Comando ejecutado en el objetivo a través del agente
scaner-pro persist install -k "clave_secreta_para_el_reinicio"
Primeros Pasos
Clona el repositorio.
Asegúrate de tener Go instalado.
Instala las dependencias:
code
```Bash
go mod tidy
Compila la herramienta:
code

```Bash
# Para pruebas
go build -o scaner-pro.exe .
```

# Para crear una versión de release
go build -o scaner-pro.exe -ldflags="-X main.currentVersion=v1.0.0" .
Configura tu entorno: Ejecuta el programa una vez para que genere el config.yml. Edítalo con tu repositorio de GitHub y, si lo deseas, las configuraciones de alerta.
Asegúrate de que Ollama está corriendo y has descargado el modelo necesario (ej. ollama pull gemma3:4b).
Bienvenido al futuro de las operaciones ofensivas. Bienvenido a SYNAPSE.

Crea un espacio de trabajo para la operación. Esto genera un directorio y un state.json que será la memoria de la IA.
```bash
scaner-pro mission start "Operacion_Quimera"
```

Dentro del chat, puedes preguntar:
resume los hallazgos.
¿cuál es el host más interesante?
propón un plan de ataque para 10.10.20.55.

### Fase 2: Infiltración y Explotación

La IA te propondrá acciones. Si las autorizas, SYNAPSE las ejecutará.
## Ejemplo de Interacción (Fuzzing):

```bash
[SYNAPSE]: He encontrado un servidor web en http://10.10.20.55:8080. Recomiendo un escaneo de directorios para encontrar un panel de administración.
[PRÓXIMA ACCIÓN RECOMENDADA]: fuzz web-dir -u http://10.10.20.55:8080 -w ./wordlists/common.txt
¿Proceder? (s/n) > s
Ejemplo de Interacción (Fuerza Bruta):
[SYNAPSE]: El escaneo ha revelado un puerto SSH en 10.10.20.70. El siguiente paso lógico es intentar un ataque de fuerza bruta con credenciales comunes.
[PRÓXIMA ACCIÓN RECOMENDADA]: bruteforce ssh -t 10.10.20.70 -U ./wordlists/users.txt -P ./wordlists/passwords.txt
¿Proceder? (s/n) > s
```

### Fase 3: Post-Explotación y Movimiento Lateral

Una vez dentro, el objetivo es expandir tu control.
Caza de Botín (Looting):
Despliega el agente en el objetivo y ordénale que busque secretos.

```Bash
# Comando enviado a través del agente C2
{
  "comando": "loot",
  "args": ["hunt", "-p", "/home", "-m", "Operacion_Quimera"]
}

## La IA analizará los resultados:
[SYNAPSE]: ¡Botín encontrado! Se ha localizado una clave privada SSH en /home/dev/.ssh/id_rsa. Recomiendo usar esta clave para intentar pivotar al host 10.10.20.90, que estaba en la misma subred.
Pivoting con Proxy SOCKS (El Portal):

Esta es la técnica definitiva para dominar la red interna.
Activa el proxy en la máquina comprometida (a través del agente C2):

```Json
{
  "comando": "pivot",
  "args": ["socks", "-p", "9050"]
}

En tu máquina de ataque, configura proxychains (o FoxyProxy en tu navegador) para usar socks5 10.10.20.70 9050.
Ahora, ataca la red interna como si estuvieras dentro:

```Bash
proxychains nmap -sT -p- 10.10.30.0/24
proxychains curl http://intranet.corp.local
```

###Fase 4: Operaciones Autónomas y Persistencia
Para operaciones a largo plazo o cuando necesitas maximizar la eficiencia.
Modo Autónomo:
Después de un escaneo inicial, puedes desatar a la IA.

```Bash
scaner-pro mission autonomous "Operacion_Quimera" -t 5m
SYNAPSE trabajará por sí solo, ejecutando escaneos, fuzzing y otras técnicas de reconocimiento en un bucle, guardando cada hallazgo y profundizando en la red. Te alertará si encuentra una brecha crítica.
Establecer Persistencia:
Una vez que tienes acceso a una máquina importante, asegúrate de que sobreviva a un reinicio.

```Bash
# Comando ejecutado en el objetivo a través del agente
scaner-pro persist install -k "clave_secreta_para_el_reinicio"

algunas funciones como arp, replay y scaneos syn necesitan https://npcap.com/dist/npcap-1.83.exe
2025 Aratan - Seed42.uk

