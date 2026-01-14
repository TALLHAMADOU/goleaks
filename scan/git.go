package scan

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitDiffFile représente un fichier modifié avec ses lignes changées
type GitDiffFile struct {
	Path    string
	Lines   []int  // Numéros de lignes ajoutées/modifiées
	Content string // Contenu du diff
}

// GetGitDiffFiles récupère les fichiers modifiés via git diff
func GetGitDiffFiles(repoPath string) ([]GitDiffFile, error) {
	// Vérifier si on est dans un repo Git
	if !isGitRepo(repoPath) {
		return nil, fmt.Errorf("le répertoire n'est pas un dépôt Git")
	}

	// Récupérer les fichiers modifiés (unstaged + staged)
	files, err := getModifiedFiles(repoPath)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return []GitDiffFile{}, nil
	}

	// Récupérer le diff pour chaque fichier
	diffFiles := make([]GitDiffFile, 0, len(files))
	for _, file := range files {
		diffContent, err := getFileDiff(repoPath, file)
		if err != nil {
			continue // Ignorer les erreurs silencieusement
		}

		lines := parseDiffLines(diffContent)
		if len(lines) > 0 {
			diffFiles = append(diffFiles, GitDiffFile{
				Path:    file,
				Lines:   lines,
				Content: diffContent,
			})
		}
	}

	return diffFiles, nil
}

// isGitRepo vérifie si le répertoire est un dépôt Git
func isGitRepo(path string) bool {
	gitDir := filepath.Join(path, ".git")
	info, err := os.Stat(gitDir)
	return err == nil && info.IsDir()
}

// getModifiedFiles récupère la liste des fichiers modifiés
func getModifiedFiles(repoPath string) ([]string, error) {
	// git diff --name-only (unstaged + staged)
	cmd := exec.Command("git", "diff", "--name-only", "--diff-filter=ACMR")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("erreur git diff: %v", err)
	}

	files := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		file := strings.TrimSpace(scanner.Text())
		if file != "" {
			files = append(files, file)
		}
	}

	// Aussi récupérer les fichiers staged
	cmd2 := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	cmd2.Dir = repoPath
	output2, err2 := cmd2.Output()
	if err2 == nil {
		scanner2 := bufio.NewScanner(strings.NewReader(string(output2)))
		for scanner2.Scan() {
			file := strings.TrimSpace(scanner2.Text())
			if file != "" {
				// Éviter les doublons
				found := false
				for _, f := range files {
					if f == file {
						found = true
						break
					}
				}
				if !found {
					files = append(files, file)
				}
			}
		}
	}

	return files, nil
}

// getFileDiff récupère le diff d'un fichier spécifique
func getFileDiff(repoPath string, filePath string) (string, error) {
	cmd := exec.Command("git", "diff", "--unified=0", filePath)
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Aussi vérifier les changements staged
	cmd2 := exec.Command("git", "diff", "--cached", "--unified=0", filePath)
	cmd2.Dir = repoPath
	output2, err2 := cmd2.Output()
	if err2 == nil && len(output2) > 0 {
		return string(output2), nil
	}

	return string(output), nil
}

// parseDiffLines parse les numéros de lignes ajoutées depuis le diff
func parseDiffLines(diffContent string) []int {
	lines := make([]int, 0)
	scanner := bufio.NewScanner(strings.NewReader(diffContent))

	var currentFile string
	for scanner.Scan() {
		line := scanner.Text()

		// Ligne @@ -x,y +z,w @@ indique le contexte
		if strings.HasPrefix(line, "@@") {
			// Extraire le numéro de ligne après le +
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Format: @@ -x,y +z,w @@
				afterPlus := parts[1]
				if strings.HasPrefix(afterPlus, "+") {
					afterPlus = afterPlus[1:]
					lineNumStr := strings.Split(afterPlus, ",")[0]
					var lineNum int
					if _, err := fmt.Sscanf(lineNumStr, "%d", &lineNum); err == nil {
						// Ajouter les lignes suivantes jusqu'à la prochaine @@
						for scanner.Scan() {
							nextLine := scanner.Text()
							if strings.HasPrefix(nextLine, "@@") {
								// Retourner au début pour traiter cette ligne
								break
							}
							if strings.HasPrefix(nextLine, "+") && !strings.HasPrefix(nextLine, "+++") {
								lines = append(lines, lineNum)
								lineNum++
							} else if !strings.HasPrefix(nextLine, "-") && !strings.HasPrefix(nextLine, "---") {
								lineNum++ // Lignes de contexte
							}
						}
					}
				}
			}
		}

		_ = currentFile // Éviter erreur unused
	}

	return lines
}

// ScanGitDiff scanne uniquement les changements Git
func ScanGitDiff(repoPath string, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		Secrets: []Secret{},
		Files:   0,
		Errors:  []string{},
	}

	// Récupérer les fichiers modifiés
	diffFiles, err := GetGitDiffFiles(repoPath)
	if err != nil {
		return nil, err
	}

	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, err
	}

	// Scanner chaque fichier modifié
	for _, diffFile := range diffFiles {
		fullPath := filepath.Join(absRepoPath, diffFile.Path)

		// Vérifier si le fichier doit être scanné
		if opts.ShouldIgnore(fullPath) {
			continue
		}

		if !opts.IsTextFile(fullPath) {
			continue
		}

		// Scanner le fichier complet (plus simple que de scanner seulement les lignes modifiées)
		secrets, scanErr := ScanFile(fullPath, opts)
		if scanErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Erreur scan %s: %v", diffFile.Path, scanErr))
			continue
		}

		// Filtrer les secrets pour ne garder que ceux sur les lignes modifiées
		if len(diffFile.Lines) > 0 {
			filteredSecrets := make([]Secret, 0)
			for _, secret := range secrets {
				for _, lineNum := range diffFile.Lines {
					if secret.Line == lineNum {
						filteredSecrets = append(filteredSecrets, secret)
						break
					}
				}
			}
			secrets = filteredSecrets
		}

		if len(secrets) > 0 {
			result.Files++
			result.Secrets = append(result.Secrets, secrets...)
		}
	}

	return result, nil
}
