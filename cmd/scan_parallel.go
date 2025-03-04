package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/joho/godotenv"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/config"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"

	"github.com/google/go-github/v48/github"
	"gopkg.in/yaml.v2"
)

// Constants for controlling resource usage
const (
	scanConcurrency = 4                 // @note you can change this value depending on the no. of threads you want to run concurrently
	reposDir        = "./repos"         // Persistent directory for repositories
	stateFile       = "scan_state.json" // File to track last run
	outputFile      = "secrets_report.md"
	scanIntervalStr = "168h" // 7 days (1 week) between scans
)

// SecretIdentifier uniquely identifies a secret within repos
type SecretIdentifier struct {
	FilePath    string
	Secret      string
	PatternName string
}

// SecretMatch represents a secret found in a commit
type SecretMatch struct {
	Commit      *object.Commit
	PatternName string
	Secret      string
	FilePath    string
	RepoURL     string
	Found       time.Time
}

// ScanState tracks the state of scanning between runs
type ScanState struct {
	LastRun        time.Time            `json:"last_run"`
	RepoLastCommit map[string]time.Time `json:"repo_last_commit"`
}

// YamlPattern defines the structure for a secret detection pattern
type YamlPattern struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
}

// YamlEntry wraps a pattern
type YamlEntry struct {
	Pattern YamlPattern `yaml:"pattern"`
}

// YamlConfig is the root structure for the rules config
type YamlConfig struct {
	Patterns []YamlEntry `yaml:"patterns"`
}

// Global counter for processed repos
var count int

// loadState loads the previous scan state from the state file
func loadState() (*ScanState, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return default state
			return &ScanState{
				LastRun:        time.Now().Add(-168 * time.Hour),
				RepoLastCommit: make(map[string]time.Time),
			}, nil
		}
		return nil, err
	}

	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// saveState saves the current scan state to the state file
func saveState(state *ScanState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(stateFile, data, 0644)
}

// loadPatterns loads secret detection patterns from the rules file
func loadPatterns(yamlFile string) ([]*regexp.Regexp, map[*regexp.Regexp]string, error) {
	data, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, nil, err
	}

	var config YamlConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, nil, err
	}

	var patterns []*regexp.Regexp
	patternNames := make(map[*regexp.Regexp]string)

	for _, entry := range config.Patterns {
		pattern := entry.Pattern.Regex

		// Clean up regex format if needed
		if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
			pattern = pattern[1 : len(pattern)-1]
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("Warning: Invalid regex '%s' for pattern '%s': %v", pattern, entry.Pattern.Name, err)
			continue
		}

		patterns = append(patterns, re)
		patternNames[re] = entry.Pattern.Name
	}

	return patterns, patternNames, nil
}

// scanDiffForSecrets looks for secrets in diff text using regex patterns
func scanDiffForSecrets(diff string, patterns []*regexp.Regexp, patternNames map[*regexp.Regexp]string) map[string]string {
	secretsWithPatterns := make(map[string]string)

	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		for _, pattern := range patterns {
			found := pattern.FindAllString(line, -1)
			if len(found) > 0 {
				for _, match := range found {
					secretsWithPatterns[match] = patternNames[pattern]
				}
			}
		}
	}

	return secretsWithPatterns
}

const reposCache = "cached_repos.json"

// FetchCachedRepos reads repositories from the cache file
func FetchCachedRepos() ([]*github.Repository, error) {
	data, err := os.ReadFile(reposCache)
	if err != nil {
		return nil, fmt.Errorf("error reading cache file: %v", err)
	}

	var repos []*github.Repository
	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, fmt.Errorf("error unmarshaling repos: %v", err)
	}

	fmt.Printf("Loaded %d repositories from cache\n", len(repos))
	return repos, nil
}

// appendToReport adds new findings to the existing report file
func appendToReport(findings []SecretMatch) error {
	// Create report file if it doesn't exist
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		_, err = f.WriteString("# Secret Scanning Results\n\n")
		if err != nil {
			return err
		}
		f.Close()
	}

	// If no findings, nothing to do
	if len(findings) == 0 {
		return nil
	}

	// Open file for appending
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Add timestamp section
	_, err = f.WriteString(fmt.Sprintf("\n## Scan Results - %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	if err != nil {
		return err
	}

	// Group findings by repository
	repoFindings := make(map[string][]SecretMatch)
	for _, match := range findings {
		repoURL := match.RepoURL
		repoFindings[repoURL] = append(repoFindings[repoURL], match)
	}

	// Write each repository's findings
	for repoURL, matches := range repoFindings {
		_, err = f.WriteString(fmt.Sprintf("### Repository: %s\n\n", repoURL))
		if err != nil {
			return err
		}

		for _, match := range matches {
			// Truncate very long secrets
			secretDisplay := match.Secret
			if len(secretDisplay) > 100 {
				secretDisplay = secretDisplay[:97] + "..."
			}

			_, err = f.WriteString(fmt.Sprintf("#### %s\n\n", match.PatternName))
			if err != nil {
				return err
			}

			_, err = f.WriteString(fmt.Sprintf("- **File:** %s\n", match.FilePath))
			if err != nil {
				return err
			}

			_, err = f.WriteString(fmt.Sprintf("- **Commit:** `%s`\n", match.Commit.Hash.String()))
			if err != nil {
				return err
			}

			_, err = f.WriteString(fmt.Sprintf("- **Author:** %s <%s>\n", match.Commit.Author.Name, match.Commit.Author.Email))
			if err != nil {
				return err
			}

			_, err = f.WriteString(fmt.Sprintf("- **Date:** %s\n", match.Commit.Author.When.Format("2006-01-02 15:04:05")))
			if err != nil {
				return err
			}

			_, err = f.WriteString(fmt.Sprintf("- **Value:** `%s`\n\n", secretDisplay))
			if err != nil {
				return err
			}

			_, err = f.WriteString("---\n\n")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func scanRepoForSecrets(repoPath, repoURL string, since time.Time, patterns []*regexp.Regexp, patternNames map[*regexp.Regexp]string, resultsCh chan<- SecretMatch) (time.Time, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return since, fmt.Errorf("opening repository: %v", err)
	}

	// Get all branches
	branches, err := repo.Branches()
	if err != nil {
		return since, fmt.Errorf("getting branches: %v", err)
	}

	// Map to track all commits by hash (to avoid duplicates)
	scanned := make(map[string]bool)
	oldestCommits := make(map[SecretIdentifier]*SecretMatch)

	// Track latest commit time
	var latestCommitTime time.Time

	// Process each branch
	err = branches.ForEach(func(ref *plumbing.Reference) error {
		commitIter, err := repo.Log(&git.LogOptions{
			From:  ref.Hash(),
			Order: git.LogOrderCommitterTime,
		})
		if err != nil {
			return fmt.Errorf("getting commit log: %v", err)
		}
		defer commitIter.Close()

		// Process commits in this branch
		err = commitIter.ForEach(func(c *object.Commit) error {
			// Only process newer commits
			if c.Committer.When.Before(since) || c.Committer.When.Equal(since) {
				return nil
			}

			// Update latest commit time if this is newer
			if c.Committer.When.After(latestCommitTime) {
				latestCommitTime = c.Committer.When
			}

			// Skip already processed commits
			if scanned[c.Hash.String()] {
				return nil
			}
			scanned[c.Hash.String()] = true

			// Process commits regardless of whether they have parents
			var diffText string

			if c.NumParents() > 0 {
				// Normal commit with parent
				parent, err := c.Parent(0)
				if err != nil {
					// Try to get content directly if we can't get the parent
					tree, err := c.Tree()
					if err == nil {
						var allFileContent strings.Builder
						tree.Files().ForEach(func(f *object.File) error {
							content, err := f.Contents()
							if err == nil {
								allFileContent.WriteString(content)
							}
							return nil
						})
						diffText = allFileContent.String()
					}
				} else {
					patch, err := parent.Patch(c)
					if err == nil {
						diffText = patch.String()
					}
				}
			} else {
				// Initial commit - get full content
				tree, err := c.Tree()
				if err == nil {
					var allFileContent strings.Builder
					tree.Files().ForEach(func(f *object.File) error {
						content, err := f.Contents()
						if err == nil {
							allFileContent.WriteString(content)
						}
						return nil
					})
					diffText = allFileContent.String()
				}
			}

			// Skip if no content to analyze
			if diffText == "" {
				return nil
			}

			// Look for secrets
			secretsWithPatterns := scanDiffForSecrets(diffText, patterns, patternNames)
			if len(secretsWithPatterns) == 0 {
				return nil
			}

			// Associate secrets with files
			var filePaths []string

			// For regular commits, get file paths from patch
			if c.NumParents() > 0 {
				parent, err := c.Parent(0)
				if err == nil {
					patch, err := parent.Patch(c)
					if err == nil {
						for _, filePatch := range patch.FilePatches() {
							from, to := filePatch.Files()
							filePath := ""
							if to != nil {
								filePath = to.Path()
							} else if from != nil {
								filePath = from.Path()
							}

							if filePath != "" {
								filePaths = append(filePaths, filePath)
							}
						}
					}
				}
			}

			// For initial commits or if patch doesn't work, get file paths from tree
			if len(filePaths) == 0 {
				tree, err := c.Tree()
				if err == nil {
					tree.Files().ForEach(func(f *object.File) error {
						filePaths = append(filePaths, f.Name)
						return nil
					})
				}
			}

			// If we still don't have file paths, use a placeholder
			if len(filePaths) == 0 {
				filePaths = append(filePaths, "unknown-file")
			}

			// For each secret, associate with files and track the oldest commit
			for secret, patternName := range secretsWithPatterns {
				if len(secret) > 500 {
					continue
				}

				// Associate with each file
				for _, filePath := range filePaths {
					id := SecretIdentifier{
						FilePath:    filePath,
						Secret:      secret,
						PatternName: patternName,
					}

					match := &SecretMatch{
						Commit:      c,
						PatternName: patternName,
						Secret:      secret,
						FilePath:    filePath,
						RepoURL:     repoURL,
						Found:       time.Now(),
					}

					existing, found := oldestCommits[id]
					if !found || c.Committer.When.Before(existing.Commit.Committer.When) {
						oldestCommits[id] = match
					}
				}
			}

			return nil
		})

		return err
	})

	// Send all secrets found
	for _, match := range oldestCommits {
		resultsCh <- *match
	}

	// Clear maps to free memory
	scanned = nil
	oldestCommits = nil

	// Force garbage collection to clean up memory
	runtime.GC()

	// Return the latest commit time we found
	if latestCommitTime.IsZero() {
		return since, err // No new commits found
	}

	return latestCommitTime, err
}

func run() {
	// Initialize count
	count = 0

	// Create persistent directories if they don't exist
	if err := os.MkdirAll(reposDir, 0755); err != nil {
		log.Fatalf("Failed to create repos directory: %v", err)
	}

	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found or error loading it")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN is not set")
	}

	// Load state from previous run
	state, err := loadState()
	if err != nil {
		log.Printf("Error loading state, starting from scratch: %v", err)
		state = &ScanState{
			LastRun:        time.Now().Add(-168 * time.Hour), // Default to 1 week ago
			RepoLastCommit: make(map[string]time.Time),
		}
	}

	patterns, patternNames, err := loadPatterns("rules.yml")
	if err != nil {
		log.Fatalf("Error loading patterns: %v", err)
	}

	org := "catalogfi"

	repos, err := FetchCachedRepos()
	if err != nil {
		log.Fatalf("Error fetching repos for org %s: %v", org, err)
	}

	resultsCh := make(chan SecretMatch, 100)
	var allFindings []SecretMatch

	// Collect results in the background
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for match := range resultsCh {
			allFindings = append(allFindings, match)
		}
	}()

	type RepoInfo struct {
		URL      string
		LocalDir string
		Exists   bool
	}

	var repoInfos []RepoInfo

	// First check which repos we already have locally
	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}

		cloneURL := repo.GetCloneURL()
		if cloneURL == "" {
			continue
		}

		// Create a normalized repo directory name from the URL
		repoName := strings.TrimSuffix(filepath.Base(cloneURL), ".git")
		repoDir := filepath.Join(reposDir, repoName)

		exists := false
		if _, err := os.Stat(repoDir); !os.IsNotExist(err) {
			exists = true
		}

		repoInfos = append(repoInfos, RepoInfo{
			URL:      cloneURL,
			LocalDir: repoDir,
			Exists:   exists,
		})
	}

	// Clone or update repositories with limited concurrency
	var repoWg sync.WaitGroup
	repoSem := make(chan struct{}, scanConcurrency)

	for _, info := range repoInfos {
		repoWg.Add(1)
		go func(info RepoInfo) {
			defer repoWg.Done()

			repoSem <- struct{}{}
			defer func() { <-repoSem }()

			auth := &http.BasicAuth{
				Username: "username", // Username doesn't matter for GitHub token auth
				Password: token,
			}

			if info.Exists {
				// Update existing repository
				fmt.Printf("Updating repository %s...\n", info.URL)

				repo, err := git.PlainOpen(info.LocalDir)
				if err != nil {
					log.Printf("Error opening repository %s: %v", info.URL, err)
					return
				}

				// Fetch updates for all branches
				err = repo.Fetch(&git.FetchOptions{
					RefSpecs: []config.RefSpec{config.RefSpec("+refs/heads/*:refs/remotes/origin/*")},
					Auth:     auth,
					Force:    true,
				})

				if err != nil && err != git.NoErrAlreadyUpToDate {
					log.Printf("Error fetching updates for repository %s: %v", info.URL, err)
				}

				// Attempt to pull updates for the current branch
				w, err := repo.Worktree()
				if err != nil {
					log.Printf("Error getting worktree for repository %s: %v", info.URL, err)
				} else {
					err = w.Pull(&git.PullOptions{
						RemoteName: "origin",
						Auth:       auth,
					})
					if err != nil && err != git.NoErrAlreadyUpToDate {
						log.Printf("Error pulling updates for repository %s: %v", info.URL, err)
					}
				}
			} else {
				// Clone new repository
				fmt.Printf("Cloning repository %s...\n", info.URL)

				_, err := git.PlainClone(info.LocalDir, false, &git.CloneOptions{
					URL:      info.URL,
					Auth:     auth,
					Progress: os.Stdout,
				})

				if err != nil {
					log.Printf("Error cloning repository %s: %v", info.URL, err)
					return
				}
			}
		}(info)
	}

	repoWg.Wait()
	fmt.Printf("Processed %d repositories\n", len(repoInfos))

	// Now scan repositories with limited concurrency
	var scanWg sync.WaitGroup
	scanSem := make(chan struct{}, scanConcurrency)

	// Create a new state to track this run
	newState := &ScanState{
		LastRun:        time.Now(),
		RepoLastCommit: make(map[string]time.Time),
	}

	for _, info := range repoInfos {
		scanWg.Add(1)
		go func(info RepoInfo) {
			defer scanWg.Done()

			scanSem <- struct{}{}
			defer func() { <-scanSem }()

			// Get the time since which we should scan
			since := state.LastRun
			if lastCommit, ok := state.RepoLastCommit[info.URL]; ok && lastCommit.After(since) {
				since = lastCommit
			}

			// Scan the repo for secrets since last check
			fmt.Printf("Scanning repository %s (changes since %s)...\n",
				info.URL, since.Format("2006-01-02 15:04:05"))

			lastCommitTime, err := scanRepoForSecrets(
				info.LocalDir,
				info.URL,
				since,
				patterns,
				patternNames,
				resultsCh,
			)

			if err != nil {
				log.Printf("Error scanning repository %s: %v", info.URL, err)
			}

			// Save the latest commit time for this repo
			if lastCommitTime.After(since) {
				newState.RepoLastCommit[info.URL] = lastCommitTime
			} else {
				newState.RepoLastCommit[info.URL] = since
			}

			count++
		}(info)
	}

	scanWg.Wait()
	close(resultsCh)
	resultsWg.Wait()

	// Write findings to report
	if err := appendToReport(allFindings); err != nil {
		log.Printf("Error writing report: %v", err)
	} else {
		log.Printf("Updated findings in %s", outputFile)
	}

	// Save state for next run
	if err := saveState(newState); err != nil {
		log.Printf("Error saving state: %v", err)
	}

	fmt.Printf("Scanned %d repositories\n", count)
	fmt.Println("Scanning complete.")
}
