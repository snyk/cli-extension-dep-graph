package pnpm

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression for the workspace name-collision: a transitive registry package
// ("shared@2.0.0") shares a name with a workspace project ("shared@1.0.0").
// The transitive one has a real version (not link:), so it must NOT be treated
// as the workspace member — its subtree ("deep") must be walked, not stop-set.
func TestBuildDepGraphs_NameCollisionIsNotStopSet(t *testing.T) {
	projects := []listProject{
		{
			Name:    "app",
			Version: "1.0.0",
			Dependencies: map[string]listDep{
				"lodash": {Version: "4.17.4", Dependencies: map[string]listDep{
					"shared": {Version: "2.0.0", Dependencies: map[string]listDep{
						"deep": {Version: "9.9.9"},
					}},
				}},
			},
		},
		{Name: "shared", Version: "1.0.0"}, // workspace project sharing the name
	}

	results, err := buildDepGraphs("", projects, "")
	if err != nil {
		t.Fatalf("buildDepGraphs: %v", err)
	}

	var appGraph string
	for _, r := range results {
		if r.graph.GetRootPkg().Info.Name == "app" {
			b, mErr := json.Marshal(r.graph)
			if mErr != nil {
				t.Fatalf("marshal graph: %v", mErr)
			}
			appGraph = string(b)
		}
	}
	if appGraph == "" {
		t.Fatal("no graph produced for app")
	}

	if !strings.Contains(appGraph, "shared@2.0.0") {
		t.Errorf("registry shared@2.0.0 should keep its real version, not the workspace 1.0.0;\n%s", appGraph)
	}
	if !strings.Contains(appGraph, "deep@9.9.9") {
		t.Errorf("subtree under the name-colliding package was dropped (the silent-skip bug);\n%s", appGraph)
	}
}

// A genuine workspace link (version "link:..") IS a stop-set leaf and renders
// as the sibling's real version from wsVersions.
func TestBuildDepGraphs_WorkspaceLinkResolvesSiblingVersion(t *testing.T) {
	projects := []listProject{
		{
			Name:    "app",
			Version: "1.0.0",
			Dependencies: map[string]listDep{
				"lib": {Version: "link:../lib", Dependencies: map[string]listDep{
					"should-not-appear": {Version: "1.2.3"},
				}},
			},
		},
		{Name: "lib", Version: "3.4.5"},
	}

	results, err := buildDepGraphs("", projects, "")
	if err != nil {
		t.Fatalf("buildDepGraphs: %v", err)
	}
	var appGraph string
	for _, r := range results {
		if r.graph.GetRootPkg().Info.Name == "app" {
			b, mErr := json.Marshal(r.graph)
			if mErr != nil {
				t.Fatalf("marshal graph: %v", mErr)
			}
			appGraph = string(b)
		}
	}
	if !strings.Contains(appGraph, "lib@3.4.5") {
		t.Errorf("workspace link should render the sibling's real version lib@3.4.5;\n%s", appGraph)
	}
	if strings.Contains(appGraph, "should-not-appear") {
		t.Errorf("workspace member subtree must not be walked in the parent graph;\n%s", appGraph)
	}
}
