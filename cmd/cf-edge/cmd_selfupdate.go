package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultGitHubAPIBase = "https://api.github.com"

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func runSelfUpdate(args []string) error {
	fs := flag.NewFlagSet("self-update", flag.ContinueOnError)
	repo := fs.String("repo", githubRepo, "GitHub repository (owner/name)")
	targetVersion := fs.String("version", "", "specific release tag (defaults to latest)")
	checkOnly := fs.Bool("check", false, "check latest version without replacing binary")
	restart := fs.Bool("restart", false, "run /etc/init.d/cf-edge restart after update")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client := &http.Client{Timeout: 60 * time.Second}
	updated, tag, err := performSelfUpdate(ctx, client, defaultGitHubAPIBase, *repo, *targetVersion, runtime.GOARCH, execPath, *checkOnly)
	if err != nil {
		return err
	}
	if *checkOnly {
		fmt.Printf("Latest release: %s (current: %s)\n", tag, version)
		return nil
	}
	if !updated {
		fmt.Printf("Already on %s\n", tag)
		return nil
	}
	fmt.Printf("Updated %s to %s\n", execPath, tag)

	if *restart {
		cmd := exec.CommandContext(ctx, "/etc/init.d/cf-edge", "restart")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("restart service failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		fmt.Println("Service /etc/init.d/cf-edge restarted")
	}
	return nil
}

func performSelfUpdate(
	ctx context.Context,
	client *http.Client,
	apiBase string,
	repo string,
	targetTag string,
	arch string,
	execPath string,
	checkOnly bool,
) (updated bool, tag string, err error) {
	rel, err := fetchRelease(ctx, client, apiBase, repo, targetTag)
	if err != nil {
		return false, "", err
	}
	if checkOnly {
		return false, rel.TagName, nil
	}
	if targetTag == "" && rel.TagName == version {
		return false, rel.TagName, nil
	}

	assetName := fmt.Sprintf("cf-edge-linux-%s", arch)
	var binURL, sumURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			binURL = a.BrowserDownloadURL
		case "checksums.txt":
			sumURL = a.BrowserDownloadURL
		}
	}
	if binURL == "" {
		return false, rel.TagName, fmt.Errorf("release %s missing asset %s", rel.TagName, assetName)
	}
	if sumURL == "" {
		return false, rel.TagName, fmt.Errorf("release %s missing checksums.txt", rel.TagName)
	}

	expectedSHA, err := fetchExpectedSHA256(ctx, client, sumURL, assetName)
	if err != nil {
		return false, rel.TagName, err
	}

	dir := filepath.Dir(execPath)
	tmpFile, err := os.CreateTemp(dir, ".cf-edge-update-*")
	if err != nil {
		return false, rel.TagName, fmt.Errorf("create temp binary: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		_ = tmpFile.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	gotSHA, err := downloadAndHash(ctx, client, binURL, tmpFile)
	if err != nil {
		return false, rel.TagName, err
	}
	if !strings.EqualFold(gotSHA, expectedSHA) {
		return false, rel.TagName, fmt.Errorf("SHA256 mismatch for %s: got %s, want %s", assetName, gotSHA, expectedSHA)
	}

	if err := tmpFile.Chmod(0755); err != nil {
		return false, rel.TagName, fmt.Errorf("chmod temp binary: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return false, rel.TagName, fmt.Errorf("sync temp binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return false, rel.TagName, err
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		return false, rel.TagName, fmt.Errorf("atomic replace %s: %w", execPath, err)
	}
	cleanup = false
	return true, rel.TagName, nil
}

func fetchRelease(ctx context.Context, client *http.Client, apiBase, repo, targetTag string) (githubRelease, error) {
	base := strings.TrimRight(apiBase, "/")
	endpoint := fmt.Sprintf("%s/repos/%s/releases/latest", base, repo)
	if targetTag != "" {
		endpoint = fmt.Sprintf("%s/repos/%s/releases/tags/%s", base, repo, targetTag)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "cf-edge-self-update")

	resp, err := client.Do(req)
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return githubRelease{}, fmt.Errorf("github releases HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return githubRelease{}, fmt.Errorf("decode release metadata: %w", err)
	}
	return rel, nil
}

func fetchExpectedSHA256(ctx context.Context, client *http.Client, sumURL, assetName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download checksums.txt HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64*1024))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && strings.TrimPrefix(fields[1], "*") == assetName {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("checksum entry for %s not found in checksums.txt", assetName)
}

func downloadAndHash(ctx context.Context, client *http.Client, url string, dst io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download binary HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
