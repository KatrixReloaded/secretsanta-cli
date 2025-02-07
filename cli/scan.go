package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v48/github"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v2"
)

// Global rate limiter: one token every 720ms.
var globalLimiter = rate.NewLimiter(rate.Every(720*time.Millisecond), 1)

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

func loadPatterns(yamlFile string) ([]*regexp.Regexp, error) {
	data, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, err
	}

	var config YamlConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	var compiledPatterns []*regexp.Regexp
	for _, entry := range config.Patterns {
		patternStr := entry.Pattern.Regex
		if strings.HasSuffix(patternStr, `(=| =|:| :)`) {
			continue
		}

		compiledPattern, err := regexp.Compile(entry.Pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern for %s: %v", entry.Pattern.Name, err)
		}
		compiledPatterns = append(compiledPatterns, compiledPattern)
	}
	return compiledPatterns, nil
}

func scanFileForSecrets(fileContent string, patterns []*regexp.Regexp) []string {
	var matches []string
	for _, pattern := range patterns {
		foundMatches := pattern.FindAllString(fileContent, -1)
		for _, match := range foundMatches {
			trimmed := strings.TrimSpace(match)
			if trimmed != "" {
				matches = append(matches, match)
			}
		}
	}
	return matches
}

// scanRepositoryFilesWithTree uses the default branch as the baseline.
// If the branch being scanned isn't the default, then files unchanged relative to
// the default branch are skipped.
func scanRepositoryFilesWithTree(client *github.Client, org, repo, branch, defaultBranch string, patterns []*regexp.Regexp) []string {
	log.Println("Scanning", repo, "on branch", branch)
	var findings []string

	var baselineMap map[string]string
	// Only build a baseline if we are not scanning the default branch.
	if branch != defaultBranch {
		// Respect the global rate limiter.
		if err := globalLimiter.Wait(context.Background()); err != nil {
			log.Printf("Rate limiter error when fetching baseline tree for %s: %v", repo, err)
		} else {
			baselineTree, _, err := client.Git.GetTree(context.Background(), org, repo, defaultBranch, true)
			if err != nil {
				log.Printf("Error getting tree for default branch %s on repo %s: %v", defaultBranch, repo, err)
			} else {
				baselineMap = make(map[string]string)
				for _, be := range baselineTree.Entries {
					if be.GetType() == "blob" {
						// Use the file path as key and blob SHA as value.
						baselineMap[be.GetPath()] = be.GetSHA()
					}
				}
			}
		}
	}

	// Fetch the tree for the current branch.
	if err := globalLimiter.Wait(context.Background()); err != nil {
		log.Printf("Rate limiter error when fetching tree for %s on branch %s: %v", repo, branch, err)
		return findings
	}
	tree, _, err := client.Git.GetTree(context.Background(), org, repo, branch, true)
	if err != nil {
		log.Printf("Error getting tree for %s on branch %s: %v", repo, branch, err)
		return findings
	}

	// Iterate through all tree entries.
	for _, entry := range tree.Entries {
		// Process only files.
		if entry.GetType() != "blob" {
			continue
		}

		lowerPath := strings.ToLower(entry.GetPath())
		if strings.EqualFold(lowerPath, "package.json") ||
			strings.EqualFold(lowerPath, "package-lock.json") ||
			strings.EqualFold(lowerPath, "yarn.lock") ||
			strings.HasSuffix(lowerPath, ".md") {
			continue
		}

		// If a baseline exists and the file is unchanged relative to the default branch, skip it.
		if baselineMap != nil {
			if baselineSHA, exists := baselineMap[entry.GetPath()]; exists && baselineSHA == entry.GetSHA() {
				continue
			}
		}

		// Respect the rate limiter before fetching file content.
		if err := globalLimiter.Wait(context.Background()); err != nil {
			log.Printf("Rate limiter error on file %q: %v", entry.GetPath(), err)
			continue
		}
		fileContent, _, _, err := client.Repositories.GetContents(
			context.Background(), org, repo, entry.GetPath(),
			&github.RepositoryContentGetOptions{Ref: branch},
		)
		if err != nil || fileContent == nil || fileContent.Content == nil {
			log.Printf("Error reading file %s in %s on branch %s: %v", entry.GetPath(), repo, branch, err)
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(*fileContent.Content)
		if err != nil {
			log.Printf("Failed to decode file %s: %v", entry.GetPath(), err)
			continue
		}

		fileStr := string(decoded)
		matches := scanFileForSecrets(fileStr, patterns)
		if len(matches) > 0 {
			findings = append(findings, fmt.Sprintf("Found secrets in %s/%s on branch %s: %v", repo, entry.GetPath(), branch, matches))
		}
	}

	return findings
}

// scanReposAndBranches launches scans for multiple branches concurrently.
// It now uses the repository's default branch directly as the baseline.
func scanReposAndBranches(client *github.Client, org string, patterns []*regexp.Regexp) {
	repos, _, err := client.Repositories.ListByOrg(context.Background(), org, &github.RepositoryListByOrgOptions{})
	if err != nil {
		log.Fatalf("Error fetching repositories: %v", err)
	}

	var wg sync.WaitGroup
	for _, repo := range repos {
		repoName := repo.GetName()
		log.Println(repoName)
		if repoName == "docs" {
			continue
		}
		// Get the default branch from the repository object.
		defaultBranch := repo.GetDefaultBranch()
		branches, _, err := client.Repositories.ListBranches(context.Background(), org, repoName, nil)
		if err != nil {
			log.Printf("Error fetching branches for %s: %v\n", repoName, err)
			continue
		}

		var defaultSHA string
		for _, b := range branches {
			if b.GetName() == defaultBranch {
				defaultSHA = b.GetCommit().GetSHA()
				break
			}
		}

		for _, branch := range branches {
			branchName := branch.GetName()

			if branchName != defaultBranch && branch.GetCommit().GetSHA() == defaultSHA {
				log.Printf("Skipping branch %s as it has the same commit hash as the default branch", branchName)
				continue
			}

			wg.Add(1)
			go func(rName, bName, defBranch string) {
				defer wg.Done()
				findings := scanRepositoryFilesWithTree(client, org, rName, bName, defBranch, patterns)
				if len(findings) > 0 {
					for _, finding := range findings {
						fmt.Println(finding)
					}
				} else {
					fmt.Printf("No secrets found for %s on branch %s.\n", rName, bName)
				}
			}(repoName, branchName, defaultBranch)
		}
	}
	fmt.Println("Done!")
	wg.Wait()
}

func getGitHubClient(token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	client := github.NewClient(oauth2.NewClient(context.Background(), ts))
	return client
}

func Execute() {
	log.Printf("Starting scan...")
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GitHub token is required. Please set the GITHUB_TOKEN environment variable.")
	}

	log.Printf("Loading patterns...")
	patterns, err := loadPatterns("rules.yml")
	if err != nil {
		log.Fatalf("Error loading patterns: %v", err)
	}

	org := "catalogfi"
	client := getGitHubClient(token)

	log.Printf("Scanning org...")
	scanReposAndBranches(client, org, patterns)
}
