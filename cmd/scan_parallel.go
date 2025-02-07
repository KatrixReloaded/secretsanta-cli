package cmd

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

// Instead of using a per-call ticker (and local limiter in scanRepositoryFiles),
// we create a global rate limiter that all API calls will share.
// With one token allowed every 720ms, you’ll be capped at roughly 5000 calls per hour.
var globalLimiter = rate.NewLimiter(rate.Every(720*time.Millisecond), 1)

// (The old apiLimiter ticker is left here if needed, but you could remove it.)
// var apiLimiter = time.NewTicker(850 * time.Millisecond)

// waitForAPICall is no longer used in our rate-limited functions,
// but it remains here if you need it for something else.
// func waitForAPICall() {
// 	// <-apiLimiter.C
// }

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

// scanRepositoryFiles now uses the shared globalLimiter instead of a local one.
// This ensures that even if you call scanRepositoryFiles concurrently (for each branch),
// all API calls are globally throttled.
// func scanRepositoryFiles(client *github.Client, org, repo, branch, rootPath string, patterns []*regexp.Regexp) []string {
// 	var findings []string

// 	findingsChan := make(chan string, 100)
// 	var wg sync.WaitGroup

// 	// A semaphore to limit the number of concurrent API calls within this branch scan.
// 	sem := make(chan struct{}, 5)

// 	// Recursive function to scan files/directories.
// 	var scanPath func(path string)
// 	scanPath = func(path string) {
// 		defer wg.Done()

// 		// Use the global rate limiter.
// 		if err := globalLimiter.Wait(context.Background()); err != nil {
// 			log.Printf("Rate limiter error on path %q: %v", path, err)
// 			return
// 		}

// 		sem <- struct{}{}
// 		file, dirs, _, err := client.Repositories.GetContents(
// 			context.Background(), org, repo, path,
// 			&github.RepositoryContentGetOptions{Ref: branch},
// 		)
// 		<-sem

// 		if err != nil {
// 			log.Printf("Error fetching contents for %s at path %q on branch %s: %v", repo, path, branch, err)
// 			return
// 		}

// 		var contents []*github.RepositoryContent
// 		if file != nil {
// 			contents = append(contents, file)
// 		}
// 		if dirs != nil {
// 			contents = append(contents, dirs...)
// 		}

// 		for _, content := range contents {
// 			if content == nil || content.Path == nil {
// 				continue
// 			}

// 			switch content.GetType() {
// 			case "dir":
// 				wg.Add(1)
// 				go scanPath(*content.Path)
// 			case "file":
// 				lowerPath := strings.ToLower(*content.Path)
// 				if strings.EqualFold(lowerPath, "package.json") ||
// 					strings.EqualFold(lowerPath, "package-lock.json") ||
// 					strings.EqualFold(lowerPath, "yarn.lock") ||
// 					strings.HasSuffix(lowerPath, ".md") {
// 					continue
// 				}

// 				wg.Add(1)
// 				go func(filePath string) {
// 					defer wg.Done()

// 					if err := globalLimiter.Wait(context.Background()); err != nil {
// 						log.Printf("Rate limiter error on file %q: %v", filePath, err)
// 						return
// 					}

// 					sem <- struct{}{}
// 					fileContent, _, _, errFile := client.Repositories.GetContents(
// 						context.Background(), org, repo, filePath,
// 						&github.RepositoryContentGetOptions{Ref: branch},
// 					)
// 					<-sem

// 					if errFile != nil || fileContent == nil || fileContent.Content == nil {
// 						log.Printf("Error reading file %s in %s on branch %s: %v", filePath, repo, branch, errFile)
// 						return
// 					}

// 					decoded, errDecode := base64.StdEncoding.DecodeString(*fileContent.Content)
// 					if errDecode != nil {
// 						log.Printf("Failed to decode file %s: %v", filePath, errDecode)
// 						return
// 					}

// 					fileStr := string(decoded)
// 					matches := scanFileForSecrets(fileStr, patterns)
// 					if len(matches) > 0 {
// 						findingsChan <- fmt.Sprintf("Found secrets in %s/%s on branch %s: %v", repo, filePath, branch, matches)
// 					}
// 				}(*content.Path)
// 			}
// 		}
// 	}

// 	wg.Add(1)
// 	go scanPath(rootPath)

// 	go func() {
// 		wg.Wait()
// 		close(findingsChan)
// 	}()

// 	for finding := range findingsChan {
// 		findings = append(findings, finding)
// 	}
// 	return findings
// }

func scanRepositoryFilesWithTree(client *github.Client, org, repo, branch string, patterns []*regexp.Regexp) []string {
	log.Println("Scanning", repo, "on branch", branch)
	var findings []string

	// Get the entire file tree recursively in one call
	tree, _, err := client.Git.GetTree(context.Background(), org, repo, branch, true)
	if err != nil {
		log.Printf("Error getting tree for %s on branch %s: %v", repo, branch, err)
		return findings
	}

	// Iterate through all tree entries
	for _, entry := range tree.Entries {
		// Filter out directories and unwanted file types
		if entry.GetType() != "blob" { // Only process files
			continue
		}
		lowerPath := strings.ToLower(entry.GetPath())
		if strings.EqualFold(lowerPath, "package.json") ||
			strings.EqualFold(lowerPath, "package-lock.json") ||
			strings.EqualFold(lowerPath, "yarn.lock") ||
			strings.HasSuffix(lowerPath, ".md") {
			continue
		}

		// Now, fetch the file content only for files you're interested in
		// (Here you might still want to obey the rate limiter)
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
// Since scanRepositoryFiles now uses a shared global rate limiter,
// even running many branch scans concurrently won’t exceed your rate limit.
func scanReposAndBranches(client *github.Client, org string, patterns []*regexp.Regexp) {
	repos, _, err := client.Repositories.ListByOrg(context.Background(), org, &github.RepositoryListByOrgOptions{})
	if err != nil {
		log.Fatalf("Error fetching repositories: %v", err)
	}
	// n := 2 // For testing: only process the first 2 repositories.
	// i := 0

	var wg sync.WaitGroup
	for _, repo := range repos {
		log.Println(*repo.Name)
		// if i >= n {
		// 	fmt.Println("Done!")
		// 	break
		// }
		// i++
		if *repo.Name == "docs" {
			continue
		}
		branches, _, err := client.Repositories.ListBranches(context.Background(), org, *repo.Name, nil)
		if err != nil {
			log.Printf("Error fetching branches for %s: %v\n", *repo.Name, err)
			continue
		}

		for _, branch := range branches {
			wg.Add(1)
			go func(rName, bName string) {
				defer wg.Done()
				// findings := scanRepositoryFiles(client, org, rName, bName, "/", patterns)
				findings := scanRepositoryFilesWithTree(client, org, rName, bName, patterns)
				if len(findings) > 0 {
					for _, finding := range findings {
						fmt.Println(finding)
					}
				} else {
					fmt.Printf("No secrets found for %s on branch %s.\n", rName, bName)
				}
			}(*repo.Name, *branch.Name)
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

func run() {
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
