package mcpserver

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

type templatesListInput struct {
	Tags []string `json:"tags,omitempty" jsonschema:"only return templates carrying at least one of these tags; empty means no filtering"`
}

type templatesListOutput struct {
	Templates []templatesync.Entry `json:"templates"`
}

func addTemplatesListTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "templates.list",
		Description: "List the bundled + synced template corpus, optionally filtered by tag.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in templatesListInput) (*mcp.CallToolResult, templatesListOutput, error) {
		dirs, labels := defaultTemplateDirsWithLabels()
		entries, _, err := templatesync.List(dirs, labels, in.Tags)
		if err != nil {
			return nil, templatesListOutput{}, err
		}
		return nil, templatesListOutput{Templates: entries}, nil
	})
}

type templatesSyncOutput struct {
	Commit         string         `json:"commit"`
	CategoryCounts map[string]int `json:"category_counts"`
}

func addTemplatesSyncTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "templates.sync",
		Description: "Sync the pinned upstream nuclei-templates categories into the local synced directory. A real network operation, same posture as 'hackerfive templates sync'.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, templatesSyncOutput, error) {
		dir, err := templatesync.DefaultSyncDir()
		if err != nil {
			return nil, templatesSyncOutput{}, err
		}
		result, err := templatesync.Sync(ctx, dir)
		if err != nil {
			return nil, templatesSyncOutput{}, err
		}
		return nil, templatesSyncOutput{Commit: result.Commit, CategoryCounts: result.CategoryCounts}, nil
	})
}

// defaultTemplateDirsWithLabels mirrors cmd/hackerfive/templates.go's own
// function of the same name (and pkg/webui's private equivalent) — see
// tools_scan.go's defaultTemplateDirs comment for why this is its own small
// copy rather than a shared import.
func defaultTemplateDirsWithLabels() (dirs, labels []string) {
	dirs = []string{templatesync.DefaultBundledDir}
	labels = []string{"bundled"}
	if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
		if _, statErr := os.Stat(syncedDir); statErr == nil {
			dirs = append(dirs, syncedDir)
			labels = append(labels, "synced")
		}
	}
	return dirs, labels
}
