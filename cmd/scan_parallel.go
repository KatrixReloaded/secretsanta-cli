package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/joho/godotenv"
	git "gopkg.in/src-d/go-git.v4" // go-git for cloning and repo access
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/yaml.v2"

	"github.com/google/go-github/v48/github"
	"golang.org/x/oauth2"
)

type YamlPattern struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
}

type YamlEntry struct {
	Pattern YamlPattern `yaml:"pattern"`
}

type YamlConfig struct {
	Patterns []YamlEntry `yaml:"patterns"`
}

type SecretIdentifier struct {
	FilePath    string
	Secret      string
	PatternName string
}

type SecretMatch struct {
	Commit      *object.Commit
	PatternName string
	Secret      string
	FilePath    string
	RepoURL     string
}

var count int

func loadPatterns(yamlFile string) ([]*regexp.Regexp, map[*regexp.Regexp]string, error) {
	data, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, nil, err
	}
	var config YamlConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, nil, err
	}

	var compiledPatterns []*regexp.Regexp
	patternNames := make(map[*regexp.Regexp]string)

	for _, entry := range config.Patterns {
		patternStr := entry.Pattern.Regex
		if strings.HasSuffix(patternStr, `(=| =|:| :)`) {
			continue
		}

		if strings.HasPrefix(patternStr, "/") && strings.HasSuffix(patternStr, "/") {
			patternStr = patternStr[1 : len(patternStr)-1]
		}

		re, err := regexp.Compile(patternStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid regex for %s: %v", entry.Pattern.Name, err)
		}
		compiledPatterns = append(compiledPatterns, re)
		patternNames[re] = entry.Pattern.Name
	}
	return compiledPatterns, patternNames, nil
}

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

func filterFalsePositives(matches []string) []string {
	var filtered []string
	ignoreSubstrings := []string{
		"yarn workspaces",
		"publish all packages",
		"run the build script",
		"workspace",
		"foreach",
	}
	for _, m := range matches {
		ignore := false
		lower := strings.ToLower(m)
		for _, substr := range ignoreSubstrings {
			if strings.Contains(lower, strings.ToLower(substr)) {
				ignore = true
				break
			}
		}
		if !ignore {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func scanRepoForSecrets(repoPath, repoURL string, patterns []*regexp.Regexp, patternNames map[*regexp.Regexp]string, resultsCh chan<- SecretMatch) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("opening repository: %v", err)
	}
	commitIter, err := repo.Log(&git.LogOptions{All: true})
	if err != nil {
		return fmt.Errorf("getting commit log: %v", err)
	}
	defer commitIter.Close()

	scanned := make(map[string]bool)

	oldestCommits := make(map[SecretIdentifier]*SecretMatch)

	err = commitIter.ForEach(func(c *object.Commit) error {
		if scanned[c.Hash.String()] {
			return nil
		}
		scanned[c.Hash.String()] = true

		if c.NumParents() == 0 {
			return nil
		}
		parent, err := c.Parent(0)
		if err != nil {
			return err
		}
		patch, err := parent.Patch(c)
		if err != nil {
			return err
		}
		diffText := patch.String()
		if diffText == "" {
			return nil
		}

		secretsWithPatterns := scanDiffForSecrets(diffText, patterns, patternNames)
		if len(secretsWithPatterns) == 0 {
			return nil
		}

		for _, filePatch := range patch.FilePatches() {
			from, to := filePatch.Files()
			filePath := ""
			if to != nil {
				filePath = to.Path()
			} else if from != nil {
				filePath = from.Path()
			}

			if filePath == "" {
				continue
			}

			// For each secret, track the oldest commit
			for secret, patternName := range secretsWithPatterns {
				if len(secret) > 500 {
					continue
				}

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
				}

				existing, found := oldestCommits[id]
				if !found || c.Committer.When.Before(existing.Commit.Committer.When) {
					oldestCommits[id] = match
				}
			}
		}

		return nil
	})

	for _, match := range oldestCommits {
		resultsCh <- *match
	}

	return err
}

// func cloneAndScanRepo(repoURL string, patterns []*regexp.Regexp, resultsCh chan<- string) {
// 	tempDir, err := os.MkdirTemp("", "repo-*")
// 	if err != nil {
// 		log.Printf("Error creating temp dir for %s: %v", repoURL, err)
// 		return
// 	}
// 	defer os.RemoveAll(tempDir)

// 	fmt.Printf("Cloning repository %s into %s...\n", repoURL, tempDir)

// 	auth := &http.BasicAuth{
// 		Username: "KatrixReloaded",
// 		Password: os.Getenv("GITHUB_TOKEN"),
// 	}

// 	_, err = git.PlainClone(tempDir, false, &git.CloneOptions{
// 		URL:      repoURL,
// 		Progress: os.Stdout,
// 		Auth:     auth,
// 	})
// 	if err != nil {
// 		log.Printf("Error cloning repository %s: %v", repoURL, err)
// 		return
// 	}

// 	if err := scanRepoForSecrets(tempDir, repoURL, patterns, resultsCh); err != nil {
// 		log.Printf("Error scanning repository %s: %v", repoURL, err)
// 	}

// 	count++
// }

func fetchOrgRepos(client *github.Client, org string) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		repos, resp, err := client.Repositories.ListByOrg(context.Background(), org, opts)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			if repo.GetName() == "docs" {
				continue
			}
			allRepos = append(allRepos, repo)
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allRepos, nil
}

func run() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found or error loading it")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN is not set")
	}

	patterns, patternNames, err := loadPatterns("rules.yml")
	if err != nil {
		log.Fatalf("Error loading patterns: %v", err)
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	ghClient := github.NewClient(tc)

	org := "catalogfi"

	repos, err := fetchOrgRepos(ghClient, org)
	if err != nil {
		log.Fatalf("Error fetching repos for org %s: %v", org, err)
	}

	// Change the channel type to match SecretMatch
	resultsCh := make(chan SecretMatch, 100)

	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		outFile := "secrets_report.md"
		f, err := os.Create(outFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer f.Close()

		// Create a more readable report format
		_, err = f.WriteString("# Secret Scanning Results\n\n")
		if err != nil {
			log.Printf("Error writing to file: %v", err)
		}

		// Group secrets by repository
		repoSecrets := make(map[string][]SecretMatch)

		for match := range resultsCh {
			// Now we can use the RepoURL field directly
			repoSecrets[match.RepoURL] = append(repoSecrets[match.RepoURL], match)
		}

		// Write secrets organized by repository
		for repo, matches := range repoSecrets {
			_, err = f.WriteString(fmt.Sprintf("## Repository: %s\n\n", repo))
			if err != nil {
				log.Printf("Error writing to file: %v", err)
			}

			for _, match := range matches {
				// Format secret - truncate if too long
				secretDisplay := match.Secret
				if len(secretDisplay) > 100 {
					secretDisplay = secretDisplay[:97] + "..."
				}

				// Write formatted entry
				_, err = f.WriteString(fmt.Sprintf("### %s\n\n", match.PatternName))
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}

				_, err = f.WriteString(fmt.Sprintf("- **File:** %s\n", match.FilePath))
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}

				_, err = f.WriteString(fmt.Sprintf("- **Commit:** `%s`\n", match.Commit.Hash.String()))
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}

				_, err = f.WriteString(fmt.Sprintf("- **Author:** %s <%s>\n", match.Commit.Author.Name, match.Commit.Author.Email))
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}

				_, err = f.WriteString(fmt.Sprintf("- **Date:** %s\n", match.Commit.Author.When.Format("2006-01-02 15:04:05")))
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}

				_, err = f.WriteString(fmt.Sprintf("- **Value:** `%s`\n\n", secretDisplay))
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}

				_, err = f.WriteString("---\n\n")
				if err != nil {
					log.Printf("Error writing to file: %v", err)
				}
			}
		}

		log.Printf("Secret findings written to %s", outFile)
	}()

	// Step 1: Clone all repositories in parallel
	type RepoInfo struct {
		URL     string
		TempDir string
	}

	var repoInfosMutex sync.Mutex
	var repoInfos []RepoInfo
	var cloneWg sync.WaitGroup

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		cloneURL := repo.GetCloneURL()
		if cloneURL == "" {
			continue
		}

		cloneWg.Add(1)
		go func(url string) {
			defer cloneWg.Done()

			tempDir, err := os.MkdirTemp("", "repo-*")
			if err != nil {
				log.Printf("Error creating temp dir for %s: %v", url, err)
				return
			}

			fmt.Printf("Cloning repository %s into %s...\n", url, tempDir)

			auth := &http.BasicAuth{
				Username: "KatrixReloaded",
				Password: token,
			}

			_, err = git.PlainClone(tempDir, false, &git.CloneOptions{
				URL:      url,
				Progress: os.Stdout,
				Auth:     auth,
			})
			if err != nil {
				log.Printf("Error cloning repository %s: %v", url, err)
				os.RemoveAll(tempDir)
				return
			}

			repoInfosMutex.Lock()
			repoInfos = append(repoInfos, RepoInfo{URL: url, TempDir: tempDir})
			repoInfosMutex.Unlock()
		}(cloneURL)
	}

	cloneWg.Wait()
	fmt.Printf("Cloned %d repositories successfully\n", len(repoInfos))

	// Step 2: Scan repositories with limited concurrency
	scanConcurrency := 6 // Limit to 6 as requested
	scanSem := make(chan struct{}, scanConcurrency)
	var scanWg sync.WaitGroup

	for _, info := range repoInfos {
		scanWg.Add(1)
		go func(tempDir, url string) {
			defer scanWg.Done()
			defer os.RemoveAll(tempDir) // Clean up temp dir after scanning

			scanSem <- struct{}{}
			if err := scanRepoForSecrets(tempDir, url, patterns, patternNames, resultsCh); err != nil {
				log.Printf("Error scanning repository %s: %v", url, err)
			}
			<-scanSem

			count++
		}(info.TempDir, info.URL)
	}

	scanWg.Wait()
	close(resultsCh)
	resultsWg.Wait()

	fmt.Println(count)
	fmt.Println("Scanning complete.")
}
