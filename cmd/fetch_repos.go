package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/google/go-github/v48/github"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

// FetchAndCacheRepos fetches repositories and stores them in cache
func FetchAndCacheRepos() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found or error loading it")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN is not set")
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	ghClient := github.NewClient(tc)

	org := "catalogfi"

	// Use the original fetchOrgRepos to get data from GitHub
	repos, err := fetchOrgRepos(ghClient, org)
	if err != nil {
		log.Fatalf("Error fetching repos for org %s: %v", org, err)
	}

	// Store the results in cache
	if err := StoreReposToCache(repos); err != nil {
		log.Fatalf("Error caching repos: %v", err)
	}

	fmt.Printf("Successfully cached %d repositories\n", len(repos))
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

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}
