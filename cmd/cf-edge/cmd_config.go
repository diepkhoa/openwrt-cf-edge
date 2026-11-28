package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/diepkhoa/openwrt-cf-edge/configs"
)

func runConfigExample(args []string) error {
	fs := flag.NewFlagSet("config-example", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	write := fs.Bool("write", false, "write config.example.yaml alongside -c config file")
	outPath := fs.String("out", "", "explicit destination file path (overrides --write)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	dest := *outPath
	if dest == "" && *write {
		dest = exampleConfigPathFor(*cfgPath)
	}
	if dest == "" {
		_, err := os.Stdout.Write(configs.ExampleYAML)
		return err
	}
	if err := writeExampleConfig(dest); err != nil {
		return err
	}
	fmt.Printf("Wrote example config to %s\n", dest)
	return nil
}

func exampleConfigPathFor(configPath string) string {
	dir := filepath.Dir(configPath)
	if dir == "" || dir == "." {
		dir = filepath.Dir(defaultConfigPath)
	}
	return filepath.Join(dir, "config.example.yaml")
}

func writeExampleConfig(dest string) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config.example-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp example config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(configs.ExampleYAML); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Chmod(0644)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	cleanup = false
	return nil
}
