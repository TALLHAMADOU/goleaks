package scan

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"secrethunter/patterns"
)

// Secret représente un secret détecté
type Secret struct {
	File          string
	Line          int
	Service       string
	Match         string // Secret masqué pour affichage
	OriginalMatch string // Secret original (non masqué) pour verify-light
	Risk          string
	Context       string // Ligne complète pour contexte
	IsHighRisk    bool   // Pour verify-light
}

// ScanResult contient les résultats du scan
type ScanResult struct {
	Secrets []Secret
	Files   int
	Errors  []string
}

// ScanOptions contient les options de scan
type ScanOptions struct {
	SmartMode      bool
	VerifyLight    bool
	DiffOnly       bool
	IgnoreDirs     []string
	IACSupport     bool
	TextExtensions map[string]bool
}

// DefaultScanOptions retourne les options par défaut
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		SmartMode:   false,
		VerifyLight: false,
		DiffOnly:    false,
		IgnoreDirs:  []string{".git", "node_modules", "vendor", "dist", "build", ".next", ".venv", "__pycache__"},
		IACSupport:  false,
		TextExtensions: map[string]bool{
			".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
			".py": true, ".java": true, ".rb": true, ".php": true, ".cs": true,
			".env": true, ".yaml": true, ".yml": true, ".json": true, ".toml": true,
			".tf": true, ".tfvars": true, ".hcl": true,
			".dockerfile": true, ".sh": true, ".bash": true, ".zsh": true,
			".md": true, ".txt": true, ".conf": true, ".config": true,
			".xml": true, ".html": true, ".css": true, ".scss": true,
		},
	}
}

// ShouldIgnore vérifie si un chemin doit être ignoré
func (opts ScanOptions) ShouldIgnore(path string) bool {
	// Vérifier les dossiers à ignorer
	for _, ignoreDir := range opts.IgnoreDirs {
		if strings.Contains(path, ignoreDir) {
			return true
		}
	}

	// Mode smart : ignorer tests/docs/exemples
	if opts.SmartMode {
		lowerPath := strings.ToLower(path)
		testPatterns := []string{"test", "spec", "example", "sample", "demo", "mock"}
		for _, pattern := range testPatterns {
			if strings.Contains(lowerPath, pattern) {
				return true
			}
		}
		// Ignorer fichiers de documentation
		if strings.Contains(lowerPath, "readme") || strings.Contains(lowerPath, "changelog") ||
			strings.Contains(lowerPath, "license") || strings.Contains(lowerPath, "contributing") {
			return true
		}
	}

	return false
}

// IsTextFile vérifie si un fichier est un fichier texte scannable
func (opts ScanOptions) IsTextFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))

	// Vérifier extension
	if opts.TextExtensions[ext] {
		return true
	}

	// Support IaC basique
	if opts.IACSupport {
		iacFiles := []string{"dockerfile", "docker-compose", "terraform", "kubernetes", "k8s"}
		lowerName := strings.ToLower(filename)
		for _, iac := range iacFiles {
			if strings.Contains(lowerName, iac) {
				return true
			}
		}
	}

	return false
}

// CalculateEntropy calcule l'entropie Shannon d'une chaîne pour détecter les secrets aléatoires
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * (p * 3.321928) // log2 via approximation
		}
	}

	return entropy
}

// IsLikelySecret vérifie si une chaîne correspondant à un pattern est probablement un secret
func IsLikelySecret(match string, context string, service string, smartMode bool) bool {
	if !smartMode {
		return true
	}

	// Vérifier l'entropie pour les patterns génériques
	entropy := CalculateEntropy(match)

	// Patterns avec entropie élevée sont probablement des secrets
	if entropy > 4.0 && len(match) > 20 {
		return true
	}

	// Vérifier si c'est un UUID (faux positif commun)
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if uuidPattern.MatchString(strings.ToLower(match)) {
		return false
	}

	// Vérifier si c'est un hash hexadécimal simple (faux positif)
	hexPattern := regexp.MustCompile(`^[a-f0-9]{32,64}$`)
	if hexPattern.MatchString(strings.ToLower(match)) && entropy < 3.5 {
		return false
	}

	// Vérifier le contexte pour certains services
	lowerContext := strings.ToLower(context)
	if service == "Algolia" && !strings.Contains(lowerContext, "algolia") {
		return false
	}
	if service == "Asana" && !strings.Contains(lowerContext, "asana") {
		return false
	}

	return true
}

// ScanFile scanne un fichier pour détecter les secrets
func ScanFile(filePath string, opts ScanOptions) ([]Secret, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var secrets []Secret
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Vérifier chaque pattern
		for _, pattern := range patterns.GetPatterns() {
			matches := pattern.Regex.FindAllString(line, -1)
			for _, match := range matches {
				if IsLikelySecret(match, line, pattern.Service, opts.SmartMode) {
					secrets = append(secrets, Secret{
						File:          filePath,
						Line:          lineNum,
						Service:       pattern.Service,
						Match:         maskSecret(match),
						OriginalMatch: match, // Secret original pour verify-light
						Risk:          pattern.Risk,
						Context:       strings.TrimSpace(line),
						IsHighRisk:    pattern.IsHighRisk,
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}

// maskSecret masque partiellement un secret pour l'affichage
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

// ScanDirectory scanne récursivement un répertoire
func ScanDirectory(rootPath string, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		Secrets: []Secret{},
		Files:   0,
		Errors:  []string{},
	}

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Erreur accès %s: %v", path, err))
			return nil
		}

		// Ignorer les dossiers
		if d.IsDir() {
			if opts.ShouldIgnore(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Vérifier si le fichier doit être scanné
		if opts.ShouldIgnore(path) {
			return nil
		}

		if !opts.IsTextFile(path) {
			return nil
		}

		result.Files++
		secrets, err := ScanFile(path, opts)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Erreur scan %s: %v", path, err))
			return nil
		}

		result.Secrets = append(result.Secrets, secrets...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// VerifySecretLight est maintenant dans verify.go
