package scan

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VerifySecretLight effectue une vérification légère d'un secret (HEAD request minimale)
func VerifySecretLight(secret Secret) bool {
	// Vérifier seulement les secrets high-risk
	if !secret.IsHighRisk {
		return true // Retourner true pour les non-high-risk (pas de vérification)
	}

	// User-agent personnalisé pour éviter les alarmes
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Construire l'URL de vérification selon le service
	url := getVerificationURL(secret.Service, secret.OriginalMatch)
	if url == "" {
		return true // Pas d'URL de vérification, considérer comme valide
	}

	// Effectuer une requête HEAD
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return true // En cas d'erreur, considérer comme valide (ne pas bloquer)
	}

	// User-agent personnalisé
	req.Header.Set("User-Agent", "SecretHunter/1.0")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", secret.OriginalMatch))

	// Effectuer la requête
	resp, err := client.Do(req)
	if err != nil {
		return true // Erreur réseau = considérer comme valide (ne pas bloquer)
	}
	defer resp.Body.Close()

	// Codes 2xx ou 401/403 indiquent que la clé est valide (même si refusée)
	// Codes 4xx autres ou 5xx = clé probablement invalide
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true // Clé valide
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true // Clé valide mais refusée (probablement expirée ou permissions)
	}

	// Autres codes = probablement invalide
	return false
}

// getVerificationURL retourne l'URL de vérification pour un service donné
func getVerificationURL(service string, _ string) string {
	service = strings.ToLower(service)

	switch service {
	case "openai":
		return "https://api.openai.com/v1/models"
	case "github pat":
		return "https://api.github.com/user"
	case "aws access key":
		return "https://sts.amazonaws.com/"
	case "stripe":
		return "https://api.stripe.com/v1/charges"
	case "azure ad":
		return "https://graph.microsoft.com/v1.0/me"
	case "alibaba":
		return "https://ecs.aliyuncs.com/"
	case "cloudflare":
		return "https://api.cloudflare.com/client/v4/user/tokens/verify"
	case "grok xai", "anthropic":
		// Pas d'URL de vérification publique disponible
		return ""
	default:
		return "" // Pas de vérification pour les autres services
	}
}
