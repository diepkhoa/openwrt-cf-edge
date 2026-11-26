package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

type validateOutput struct {
	Valid   bool   `json:"valid"`
	Config  string `json:"config"`
	Node    string `json:"node,omitempty"`
	Records int    `json:"records,omitempty"`
	Error   string `json:"error,omitempty"`
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	jsonOut := fs.Bool("json", false, "output validation result as JSON")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	return executeValidate(os.Stdout, *cfgPath, *jsonOut)
}

func executeValidate(w io.Writer, cfgPath string, jsonOut bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if jsonOut {
			_ = json.NewEncoder(w).Encode(validateOutput{
				Valid:  false,
				Config: cfgPath,
				Error:  err.Error(),
			})
		}
		return err
	}

	if jsonOut {
		return json.NewEncoder(w).Encode(validateOutput{
			Valid:   true,
			Config:  cfgPath,
			Node:    cfg.NodeName,
			Records: len(cfg.Cloudflare.Records),
		})
	}
	fmt.Fprintf(w, "Config valid (node=%s, records=%d, path=%s)\n", cfg.NodeName, len(cfg.Cloudflare.Records), cfgPath)
	return nil
}

type versionOutput struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	Repo      string `json:"repo"`
	OS        string `json:"os"`
}

func runVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "output version info as JSON")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}
	return renderVersion(os.Stdout, *jsonOut)
}

func renderVersion(w io.Writer, jsonOut bool) error {
	if jsonOut {
		return json.NewEncoder(w).Encode(versionOutput{
			Version:   version,
			Commit:    commit,
			BuildDate: buildDate,
			Repo:      githubRepo,
			OS:        runtime.GOOS + "/" + runtime.GOARCH,
		})
	}
	fmt.Fprintf(w, "cf-edge %s (commit=%s built=%s repo=%s)\n", version, commit, buildDate, githubRepo)
	return nil
}
