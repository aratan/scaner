// FICHERO: config.go
package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

// --- ESTRUCTURAS DE CONFIGURACIÓN ---

type SMTPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Server    string `yaml:"server"`
	Port      int    `yaml:"port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	Recipient string `yaml:"recipient"`
}

type AlertConfig struct {
	SMTP SMTPConfig `yaml:"smtp"`
}

type C2Profile struct {
	UserAgent string `yaml:"user_agent"`
	Endpoint  string `yaml:"endpoint"`
}

type AppConfig struct {
	GitHubRepo         string               `yaml:"github_repo"`
	DefaultOllamaModel string               `yaml:"default_ollama_model"`
	Alerts             AlertConfig          `yaml:"alerts"`
	AgentProfiles      map[string]C2Profile `yaml:"agent_profiles"`
}

// --- VARIABLE GLOBAL PARA LA CONFIGURACIÓN ---
var ConfigData AppConfig

// init() es una función especial en Go que se ejecuta automáticamente ANTES de la función main().
// Es el lugar perfecto para cargar la configuración.
func init() {
	loadConfig()
}

// loadConfig se encarga de leer config.yml o cargar valores por defecto si falla.
func loadConfig() {
	configPath := "config.yml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Println("ADVERTENCIA: No se encontró el fichero 'config.yml'. Creando uno con valores por defecto.")
		createDefaultConfigFile(configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Println("ADVERTENCIA: No se pudo leer 'config.yml'. Cargando configuración por defecto en memoria.")
		loadDefaultConfigInMemory()
		return
	}

	err = yaml.Unmarshal(data, &ConfigData)
	if err != nil {
		log.Println("ADVERTENCIA: 'config.yml' está mal formado. Cargando configuración por defecto en memoria.")
		loadDefaultConfigInMemory()
		return
	}

	log.Println("Configuración cargada correctamente desde 'config.yml'.")
}

// loadDefaultConfigInMemory establece los valores por defecto si no se puede usar el fichero.
func loadDefaultConfigInMemory() {
	ConfigData = AppConfig{
		GitHubRepo:         "aratan/SYNAPSE", // VALOR FIJO SI NO HAY FICHERO
		DefaultOllamaModel: "gemma3:4b",
		Alerts:             AlertConfig{SMTP: SMTPConfig{Enabled: false}},
		AgentProfiles: map[string]C2Profile{
			"default": {
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
				Endpoint:  "/api/v1/data",
			},
		},
	}
}

// createDefaultConfigFile genera un fichero config.yml con una plantilla por defecto.
func createDefaultConfigFile(path string) {
	defaultConfig := AppConfig{
		GitHubRepo:         "tu_usuario_github/tu_repositorio",
		DefaultOllamaModel: "gemma3:4b",
		Alerts: AlertConfig{
			SMTP: SMTPConfig{
				Enabled:   false,
				Server:    "smtp.example.com",
				Port:      587,
				Username:  "tu_email@example.com",
				Password:  "tu_contraseña_de_aplicacion",
				Recipient: "alerta_pentest@example.com",
			},
		},
		AgentProfiles: map[string]C2Profile{
			"default": {
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
				Endpoint:  "/api/v1/data",
			},
		},
	}

	data, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		log.Printf("Error interno al generar la configuración por defecto: %v", err)
		return
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		log.Printf("ADVERTENCIA: No se pudo escribir el fichero de configuración en '%s' (probablemente por falta de permisos): %v", path, err)
	}
}
