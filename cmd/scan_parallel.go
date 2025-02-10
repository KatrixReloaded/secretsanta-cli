package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

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
		re, err := regexp.Compile(patternStr)
		if err != nil {
			return nil, fmt.Errorf("invalid regex for %s: %v", entry.Pattern.Name, err)
		}
		compiledPatterns = append(compiledPatterns, re)
	}
	return compiledPatterns, nil
}

func scanDiffForSecrets(diff string, patterns []*regexp.Regexp) []string {
	var matches []string
	for _, pattern := range patterns {
		found := pattern.FindAllString(diff, -1)
		if len(found) > 0 {
			matches = append(matches, found...)
		}
	}
	return matches
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

func scanRepoForSecrets(repoPath, repoURL string, patterns []*regexp.Regexp, resultsCh chan<- string) error {
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
		matches := scanDiffForSecrets(diffText, patterns)
		matches = filterFalsePositives(matches)
		if len(matches) > 0 {
			result := fmt.Sprintf("## Repository: %s  \n#### **Commit:** `%s`  \n#### **By:** %s  \n#### **Matches:** `%v`  \n  \n", repoURL, c.Hash, c.Author.Name, matches)
			resultsCh <- result
		}
		return nil
	})
	return err
}

func cloneAndScanRepo(repoURL string, patterns []*regexp.Regexp, resultsCh chan<- string) {
	tempDir, err := os.MkdirTemp("", "repo-*")
	if err != nil {
		log.Printf("Error creating temp dir for %s: %v", repoURL, err)
		return
	}
	defer os.RemoveAll(tempDir)

	fmt.Printf("Cloning repository %s into %s...\n", repoURL, tempDir)

	_, err = git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
	})
	if err != nil {
		log.Printf("Error cloning repository %s: %v", repoURL, err)
		return
	}

	if err := scanRepoForSecrets(tempDir, repoURL, patterns, resultsCh); err != nil {
		log.Printf("Error scanning repository %s: %v", repoURL, err)
	}
}

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
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN is not set")
	}

	patterns, err := loadPatterns("rules.yml")
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

	resultsCh := make(chan string, 100)

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
		for res := range resultsCh {
			_, err := f.WriteString(res + "\n")
			if err != nil {
				log.Printf("Error writing to file: %v", err)
			}
		}
		log.Printf("Secret findings written to %s", outFile)
	}()

	concurrencyLimit := 8
	sem := make(chan struct{}, concurrencyLimit)
	var wg sync.WaitGroup

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		cloneURL := repo.GetCloneURL()
		if cloneURL == "" {
			continue
		}

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			cloneAndScanRepo(url, patterns, resultsCh)
			<-sem
		}(cloneURL)
	}

	wg.Wait()
	fmt.Println("Scanning complete.")
}
