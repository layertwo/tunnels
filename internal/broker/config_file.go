package broker

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// serverFile is the `[server]` section: the process itself. Every field is a pointer so an absent key
// is distinct from one present and empty.
type serverFile struct {
	ListenAddr *string `toml:"listen_addr"`
	LogLevel   *string `toml:"log_level"`
}

// identityFile is the `[identity]` section: the OIDC issuer and the API the CLI logs in against.
type identityFile struct {
	Issuer        *string `toml:"issuer"`
	APIResource   *string `toml:"api_resource"`
	CreatorsGroup *string `toml:"creators_group"`
	CLIClientID   *string `toml:"cli_client_id"`
	MinCLIVersion *string `toml:"min_cli_version"`
	UsernameClaim *string `toml:"username_claim"`
	GroupsClaim   *string `toml:"groups_claim"`
}

// tunnelsFile is the `[tunnels]` section: the tunnel service itself, always on.
type tunnelsFile struct {
	ServiceHost       *string `toml:"service_host"`
	SitesDomain       *string `toml:"sites_domain"`
	MaxTunnelsPerUser *int    `toml:"max_tunnels_per_user"`
	BandwidthLimit    *string `toml:"bandwidth_limit"`
	// A nil slice is an absent key; an empty non-nil slice is an explicit empty list.
	ReservedHandles []string `toml:"reserved_handles"`
}

// machinesFile is the `[machines]` section: a switchable feature. The API key is not here;
// POCKET_ID_API_KEY stays in the environment.
type machinesFile struct {
	Enabled       *bool   `toml:"enabled"`
	PocketIDURL   *string `toml:"pocket_id_url"`
	PocketIDAPIID *string `toml:"pocket_id_api_id"`
}

// metricsFile is the `[metrics]` section: a switchable feature.
type metricsFile struct {
	Enabled *bool `toml:"enabled"`
}

// FileConfig is the config file's schema. A section pointer is nil when the section is absent, which
// is how a feature with no section reads as off.
type FileConfig struct {
	Server   *serverFile   `toml:"server"`
	Identity *identityFile `toml:"identity"`
	Tunnels  *tunnelsFile  `toml:"tunnels"`
	Machines *machinesFile `toml:"machines"`
	Metrics  *metricsFile  `toml:"metrics"`
}

// secretKeys are settings that must never appear in the file: it is world-readable and committed, so a
// secret lives in the environment (a mounted Secret) only. A key naming one is a startup error.
var secretKeys = map[string]bool{
	"database_url":            true,
	"pocket_id_api_key":       true,
	"frps_dashboard_password": true,
	"plugin_secret":           true,
}

// ParseFile decodes a TOML document. It is strict: an unknown key or section (a typo like `[machine]`),
// or a key naming a secret, is an error naming the key and never its value. A missing section is nil.
func ParseFile(data []byte) (*FileConfig, error) {
	// Decode loosely first: findSecret must also see sections and array-of-tables the strict decoder
	// rejects, so a key under one is still named as a secret rather than as an unknown key.
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	if name := findSecret(raw); name != "" {
		return nil, fmt.Errorf("config file: %s is a secret and must not be in the file", name)
	}

	var fc FileConfig
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			keys := make([]string, 0, len(strict.Errors))
			for _, d := range strict.Errors {
				keys = append(keys, strings.Join(d.Key(), "."))
			}
			return nil, fmt.Errorf("config file: unknown key %s", strings.Join(keys, ", "))
		}
		return nil, fmt.Errorf("config file: %w", err)
	}
	return &fc, nil
}

// findSecret walks a decoded document for a key that names a secret, at any depth, and returns the key
// as written, or "".
func findSecret(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			if secretKeys[strings.ToLower(k)] {
				return k
			}
			if name := findSecret(sub); name != "" {
				return name
			}
		}
	case []any:
		for _, sub := range t {
			if name := findSecret(sub); name != "" {
				return name
			}
		}
	}
	return ""
}
