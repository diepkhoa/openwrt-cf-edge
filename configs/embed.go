package configs

import _ "embed"

// ExampleYAML holds configs/config.example.yaml embedded at build time
// so cf-edge self-update can refresh config.example.yaml alongside config.yaml.
//
//go:embed config.example.yaml
var ExampleYAML []byte
