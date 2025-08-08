// FICHERO: update.go
package main

import (
	"log"
	"strings"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

// Esta variable será inyectada en tiempo de compilación por el flag -ldflags.
var currentVersion string

// NewUpdateCmd crea el comando 'update'.
func NewUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Actualiza la herramienta a la última versión desde GitHub",
		Long: `Comprueba si hay una nueva versión disponible en los "Releases" del repositorio
de GitHub configurado en config.yml. Si existe, la descarga y reemplaza el ejecutable actual.`,
		Run: func(cmd *cobra.Command, args []string) {
			doSelfUpdate()
		},
	}
	return cmd
}

// doSelfUpdate contiene la lógica principal para el proceso de auto-actualización.
func doSelfUpdate() {
	// --- Verificación 1: ¿Se compiló con una versión? ---
	if currentVersion == "" {
		log.Fatal("Error: Versión actual desconocida. La herramienta debe ser compilada con el flag '-ldflags=\"-X main.currentVersion=vX.Y.Z\"' para poder actualizarse.")
	}

	// --- Verificación 2: ¿Está configurado el repositorio en config.yml? ---
	// Usamos la variable global 'ConfigData' que se carga desde config.go al inicio.
	githubRepo := ConfigData.GitHubRepo
	if githubRepo == "tu_usuario_github/tu_repositorio" || githubRepo == "" {
		log.Fatal("Error: El repositorio de GitHub no ha sido configurado. Por favor, edita el valor 'github_repo' en el fichero 'config.yml'.")
	}

	log.Printf("Versión actual: %s", currentVersion)
	log.Printf("Buscando actualizaciones en el repositorio de GitHub: %s", githubRepo)

	// --- Lógica de Actualización ---

	// 1. La librería semver no acepta la 'v' al principio del string de versión.
	version_sin_v := strings.TrimPrefix(currentVersion, "v")

	// 2. Convertimos nuestro string de versión a un objeto semver para poder compararlo.
	parsedVersion, err := semver.Make(version_sin_v)
	if err != nil {
		log.Fatalf("Error: La versión compilada ('%s') no es una versión semántica válida: %v", currentVersion, err)
	}

	// 3. La librería se conecta a GitHub, encuentra el último release, y lo compara con nuestra versión.
	latest, err := selfupdate.UpdateSelf(parsedVersion, githubRepo)
	if err != nil {
		log.Fatalf("Error durante el proceso de actualización: %v", err)
	}

	// 4. Comparamos la versión del último release con nuestra versión actual.
	if latest.Version.Equals(parsedVersion) {
		log.Printf("¡Estás al día! La versión %s ya es la última disponible.", currentVersion)
	} else {
		log.Printf("¡Actualización completada con éxito a la versión v%s!", latest.Version)
		log.Println("Notas de la versión:", latest.ReleaseNotes)
	}
}