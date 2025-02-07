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

	"github.com/google/go-github/v48/github"

	"gopkg.in/yaml.v2"

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

func scanRepositoryFiles(client *github.Client, org, repo, branch, path string, patterns []*regexp.Regexp) []string {
	var findings []string

	file, dirs, resp, err := client.Repositories.GetContents(
		context.Background(), org, repo, path,
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		log.Printf("Error fetching contents for %s at path %q on branch %s: %v\n", repo, path, branch, err)
		return findings
	}
	_ = resp

	var contents []*github.RepositoryContent
	if file != nil {
		contents = append(contents, file)
	}
	if dirs != nil {
		contents = append(contents, dirs...)
	}

	for _, content := range contents {
		switch content.GetType() {
		case "file":
			if strings.EqualFold(*content.Path, "package.json") ||
				strings.HasSuffix(strings.ToLower(*content.Path), ".md") {
				continue
			}
			fileContent, _, respFile, errFile := client.Repositories.GetContents(
				context.Background(), org, repo, *content.Path,
				&github.RepositoryContentGetOptions{Ref: branch},
			)
			if errFile != nil {
				log.Printf("Error reading file %s in %s: %v\n", *content.Path, repo, errFile)
				continue
			}
			_ = respFile

			decoded, errDecode := base64.StdEncoding.DecodeString(*fileContent.Content)
			if errDecode != nil {
				log.Printf("Failed to decode file %s: %v", *content.Path, errDecode)
				continue
			}

			fileStr := string(decoded)
			matches := scanFileForSecrets(fileStr, patterns)
			if len(matches) > 0 {
				findings = append(findings, fmt.Sprintf("Found secrets in %s/%s on branch %s: %v",
					repo, *content.Path, branch, matches))
			}
		case "dir":
			// Recursively scan the subdirectory.
			subFindings := scanRepositoryFiles(client, org, repo, branch, *content.Path, patterns)
			findings = append(findings, subFindings...)
		}
	}

	return findings
}

func scanReposAndBranches(client *github.Client, org string, patterns []*regexp.Regexp) {
	repos, _, err := client.Repositories.ListByOrg(context.Background(), org, &github.RepositoryListByOrgOptions{})
	if err != nil {
		log.Fatalf("Error fetching repositories: %v", err)
	}
	n := 2 // For testing: only process the first 2 repositories.
	i := 0

	var wg sync.WaitGroup
	for _, repo := range repos {
		if i >= n {
			fmt.Println("Done!")
			break
		}
		i++
		branches, _, err := client.Repositories.ListBranches(context.Background(), org, *repo.Name, nil)
		if err != nil {
			log.Printf("Error fetching branches for %s: %v\n", *repo.Name, err)
			continue
		}

		for _, branch := range branches {
			wg.Add(1)
			// Note: pass "/" as the starting path.
			go func(rName, bName string) {
				defer wg.Done()
				log.Printf("Scanning files in %s branch %s...\n", rName, bName)
				findings := scanRepositoryFiles(client, org, rName, bName, "/", patterns)
				if len(findings) > 0 {
					fmt.Printf("Findings for %s on branch %s:\n", rName, bName)
					for _, finding := range findings {
						fmt.Println(finding)
					}
				} else {
					fmt.Printf("No secrets found for %s on branch %s.\n", rName, bName)
				}
			}(*repo.Name, *branch.Name)
		}
	}
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
