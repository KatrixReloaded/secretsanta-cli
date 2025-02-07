package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/google/go-github/v48/github"
	"github.com/pelletier/go-toml"
	"golang.org/x/oauth2"
)

type Rule struct {
	Description string `toml:"description"`
	Regex       string `toml:"regex"`
}

type Config struct {
	Rules []Rule `toml:"rules"`
}

func loadPatterns(tomlFile string) ([]*regexp.Regexp, error) {
	tree, err := toml.LoadFile(tomlFile)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := tree.Unmarshal(&config); err != nil {
		return nil, err
	}

	var compiledPatterns []*regexp.Regexp
	for _, rule := range config.Rules {
		compiledPattern, err := regexp.Compile(rule.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %v", err)
		}
		compiledPatterns = append(compiledPatterns, compiledPattern)
	}
	return compiledPatterns, nil
}

func scanFileForSecrets(fileContent string, patterns []*regexp.Regexp) []string {
	var matches []string
	for _, pattern := range patterns {
		foundMatches := pattern.FindAllString(fileContent, -1)
		matches = append(matches, foundMatches...)
	}
	return matches
}

func scanRepositoryFiles(client *github.Client, org, repo, branch string, patterns []*regexp.Regexp) []string {
	log.Printf("Scanning files %s...\n", branch)
	var findings []string

	file, dirs, resp, err := client.Repositories.GetContents(
		context.Background(), org, repo, "/",
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		log.Printf("Error fetching contents for %s on branch %s: %v\n", repo, branch, err)
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
		if content.GetType() == "file" {
			fileContent, _, respFile, errFile := client.Repositories.GetContents(
				context.Background(), org, repo, *content.Path,
				&github.RepositoryContentGetOptions{Ref: branch},
			)
			if errFile != nil {
				log.Printf("Error reading file %s in %s: %v\n", *content.Path, repo, errFile)
				continue
			}
			_ = respFile

			fileStr := *fileContent.Content
			matches := scanFileForSecrets(fileStr, patterns)
			if len(matches) > 0 {
				findings = append(findings, fmt.Sprintf("Found secrets in %s/%s on branch %s: %v",
					repo, *content.Path, branch, matches))
			}
		} else if content.GetType() == "dir" {
			subFindings := scanRepositoryFiles(client, org, repo, branch, patterns)
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

	for _, repo := range repos {
		branches, _, err := client.Repositories.ListBranches(context.Background(), org, *repo.Name, nil)
		if err != nil {
			log.Printf("Error fetching branches for %s: %v\n", *repo.Name, err)
			continue
		}

		for _, branch := range branches {
			log.Printf("Scanning %s on branch %s...\n", *repo.Name, *branch.Name)
			findings := scanRepositoryFiles(client, org, *repo.Name, *branch.Name, patterns)
			if len(findings) > 0 {
				fmt.Printf("Findings for %s on branch %s:\n", *repo.Name, *branch.Name)
				for _, finding := range findings {
					fmt.Println(finding)
				}
			}
		}
	}
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
	patterns, err := loadPatterns("regex.toml")
	if err != nil {
		log.Fatalf("Error loading patterns: %v", err)
	}

	org := "catalogfi"

	client := getGitHubClient(token)

	log.Printf("Scanning org...")
	scanReposAndBranches(client, org, patterns)
}
