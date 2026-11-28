package main

import (
	"fmt"
	"os"
)

const defaultConfigPath = "/etc/cf-edge/config.yaml"

var (
	version    = "dev"
	commit     = "none"
	buildDate  = "unknown"
	githubRepo = "diepkhoa/openwrt-cf-edge"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cf-edge error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	syncLocalTimezone()

	if len(args) == 0 {
		printUsage()
		return fmt.Errorf("missing subcommand")
	}

	switch args[0] {
	case "daemon":
		return runDaemon(args[1:])
	case "update":
		return runUpdate(args[1:])
	case "status":
		return runStatus(args[1:])
	case "shield":
		return runShield(args[1:])
	case "firewall":
		return runFirewall(args[1:])
	case "self-update":
		return runSelfUpdate(args[1:])
	case "config-example":
		return runConfigExample(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "restart":
		return runRestart(args[1:])
	case "version", "--version", "-v":
		return runVersion(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage() {
	fmt.Println(`cf-edge - OpenWrt Event-Driven Cloudflare DDNS, PPPoE Guard, Edge Firewall & DDoS Shield

Usage:
  cf-edge daemon
  cf-edge update [--force]
  cf-edge status [--json]
  cf-edge validate [--json]
  cf-edge restart
  cf-edge shield <enter [--no-redial] | exit | status>
  cf-edge firewall <render | apply [--refresh] | remove | status [--json]>
  cf-edge self-update [--check] [--version vX.Y.Z] [--no-restart]
  cf-edge config-example [--write]
  cf-edge version [--json]

Global option: -c <path> (default: /etc/cf-edge/config.yaml)`)
}
