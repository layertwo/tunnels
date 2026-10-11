package broker

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

const goodSecret = "0123456789abcdef0123456789abcdef"

// allVars is a complete, valid environment.
func allVars() map[string]string {
	return map[string]string{
		"SERVICE_HOST":            "tunnels.layertwo.dev",
		"SITES_DOMAIN":            "w.tunnels.layertwo.dev",
		"ISSUER":                  "https://idp.layertwo.dev",
		"API_RESOURCE":            "https://tunnels.layertwo.dev",
		"CREATORS_GROUP":          "tunnels-creators",
		"USERNAME_CLAIM":          "nickname",
		"GROUPS_CLAIM":            "roles",
		"CLI_CLIENT_ID":           "tunnels-cli",
		"MIN_CLI_VERSION":         "0.2.0",
		"DATABASE_URL":            "postgres://broker:pw@db:5432/tunnels",
		"FRPS_DASHBOARD_URL":      "http://frps.tunnels.svc:7500",
		"FRPS_DASHBOARD_USER":     "broker",
		"FRPS_DASHBOARD_PASSWORD": "dash-pw",
		"PLUGIN_SECRET":           goodSecret,
		"MAX_TUNNELS_PER_USER":    "3",
		"DEFAULT_BANDWIDTH_LIMIT": "2MB",
		"RESERVED_HANDLES":        "admin, Root,,ops ",
		"LISTEN_ADDR":             "127.0.0.1:9000",
		"LOG_LEVEL":               "debug",
	}
}

func load(vars map[string]string) (Config, error) {
	return LoadConfig(func(k string) string { return vars[k] })
}

var required = []string{
	"SERVICE_HOST", "SITES_DOMAIN", "ISSUER", "API_RESOURCE", "CREATORS_GROUP", "CLI_CLIENT_ID",
	"DATABASE_URL", "FRPS_DASHBOARD_URL", "FRPS_DASHBOARD_USER", "FRPS_DASHBOARD_PASSWORD", "PLUGIN_SECRET",
}

func TestLoadConfig(t *testing.T) {
	got, err := load(allVars())
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		ServiceHost: "tunnels.layertwo.dev", SitesDomain: "w.tunnels.layertwo.dev",
		Issuer: "https://idp.layertwo.dev", APIResource: "https://tunnels.layertwo.dev",
		CreatorsGroup: "tunnels-creators", UsernameClaim: "nickname", GroupsClaim: "roles",
		CLIClientID: "tunnels-cli", MinCLIVersion: "0.2.0",
		DatabaseURL:      "postgres://broker:pw@db:5432/tunnels",
		FrpsDashboardURL: "http://frps.tunnels.svc:7500", FrpsDashboardUser: "broker", FrpsDashboardPassword: "dash-pw",
		PluginSecret: goodSecret, MaxTunnelsPerUser: 3, BandwidthLimit: "2MB",
		Reserved: []string{"admin", "root", "ops"}, ListenAddr: "127.0.0.1:9000", LogLevel: slog.LevelDebug,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	vars := map[string]string{}
	for _, k := range required {
		vars[k] = allVars()[k]
	}
	got, err := load(vars)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsernameClaim != "preferred_username" || got.GroupsClaim != "groups" || got.MinCLIVersion != "0.0.0" ||
		got.MaxTunnelsPerUser != 5 || got.BandwidthLimit != "10MB" || got.ListenAddr != ":8080" || got.LogLevel != slog.LevelInfo ||
		!reflect.DeepEqual(got.Reserved, []string{"admin", "root", "support", "security"}) {
		t.Errorf("defaults = %+v", got)
	}
}

func TestLoadConfigMachineClients(t *testing.T) {
	t.Run("parses, trims and lowercases the handle", func(t *testing.T) {
		vars := allVars()
		vars["MACHINE_CLIENTS"] = " id1 = Alice , id2=BOX ,"
		got, err := load(vars)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"id1": "alice", "id2": "box"}
		if !reflect.DeepEqual(got.MachineClients, want) {
			t.Errorf("MachineClients = %v, want %v", got.MachineClients, want)
		}
	})
	for _, value := range []string{"id1=", "=alice", "id1=a", "id1=Al ice"} {
		t.Run("rejects "+value, func(t *testing.T) {
			vars := allVars()
			vars["MACHINE_CLIENTS"] = value
			if _, err := load(vars); err == nil || !strings.Contains(err.Error(), "MACHINE_CLIENTS") {
				t.Fatalf("err = %v, want one naming MACHINE_CLIENTS", err)
			}
		})
	}
	t.Run("absent is nil", func(t *testing.T) {
		got, err := load(allVars())
		if err != nil || got.MachineClients != nil {
			t.Errorf("MachineClients = %v, %v, want nil", got.MachineClients, err)
		}
	})
	t.Run("empty is nil", func(t *testing.T) {
		vars := allVars()
		vars["MACHINE_CLIENTS"] = ""
		got, err := load(vars)
		if err != nil || got.MachineClients != nil {
			t.Errorf("MachineClients = %v, %v, want nil", got.MachineClients, err)
		}
	})
	t.Run("a pair without an equals sign", func(t *testing.T) {
		vars := allVars()
		vars["MACHINE_CLIENTS"] = "id1=alice,junk"
		if _, err := load(vars); err == nil || !strings.Contains(err.Error(), "MACHINE_CLIENTS") {
			t.Fatalf("err = %v, want one naming MACHINE_CLIENTS", err)
		}
	})
}

func TestLoadConfigRequired(t *testing.T) {
	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			vars := allVars()
			delete(vars, name)
			if _, err := load(vars); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("without %s: err = %v, want one naming it", name, err)
			}
			vars[name] = ""
			if _, err := load(vars); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("with %s empty: err = %v, want one naming it", name, err)
			}
		})
	}
}

// Everything that is wrong is reported at once, so one restart fixes all of it.
func TestLoadConfigReportsEveryProblem(t *testing.T) {
	_, err := load(map[string]string{"MAX_TUNNELS_PER_USER": "x"})
	if err == nil {
		t.Fatal("no error")
	}
	for _, name := range append([]string{"MAX_TUNNELS_PER_USER"}, required...) {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name %s: %v", name, err)
		}
	}
}

func TestLoadConfigRejects(t *testing.T) {
	tests := []struct {
		name, value string
	}{
		{"MAX_TUNNELS_PER_USER", "x"},
		{"MAX_TUNNELS_PER_USER", "0"},
		{"MAX_TUNNELS_PER_USER", "-1"},
		{"MAX_TUNNELS_PER_USER", "1.5"},
		{"MAX_TUNNELS_PER_USER", "5 "},
		{"LOG_LEVEL", "loud"},
		{"LISTEN_ADDR", "8080"},
		{"LISTEN_ADDR", "localhost"},
		// frps ignores a limit it cannot parse and then limits nothing, so these must not get through.
		{"DEFAULT_BANDWIDTH_LIMIT", "10Mb"},
		{"DEFAULT_BANDWIDTH_LIMIT", "10mb"},
		{"DEFAULT_BANDWIDTH_LIMIT", "10"},
		{"DEFAULT_BANDWIDTH_LIMIT", "10MBps"},
		{"DEFAULT_BANDWIDTH_LIMIT", "fast"},
		{"DEFAULT_BANDWIDTH_LIMIT", "0MB"},
		{"DEFAULT_BANDWIDTH_LIMIT", "-5MB"},
		{"DEFAULT_BANDWIDTH_LIMIT", "0.0001KB"},
		// The sites domain is compared with every host Traefik forwards.
		{"SITES_DOMAIN", "w.tunnels.layertwo.dev."},
		{"SITES_DOMAIN", "w.tunnels.layertwo.dev:443"},
		{"SITES_DOMAIN", ".w.tunnels.layertwo.dev"},
		{"SITES_DOMAIN", "w..tunnels.layertwo.dev"},
		{"SITES_DOMAIN", "*.w.tunnels.layertwo.dev"},
		{"SITES_DOMAIN", "https://w.tunnels.layertwo.dev"},
		{"SITES_DOMAIN", "w.tunnels.layertwo.dev/"},
		{"SITES_DOMAIN", "w tunnels"},
		{"SITES_DOMAIN", "w_x.layertwo.dev"},
		{"SITES_DOMAIN", "-w.layertwo.dev"},
		{"SITES_DOMAIN", "w.layertwo.dev,x.layertwo.dev"},
		{"SITES_DOMAIN", "w.\u212Aelvin.dev"}, // strings.ToLower makes it "w.kelvin.dev"
		{"SERVICE_HOST", "\u212Aelvin.dev"},
		{"SITES_DOMAIN", "w.ünal.dev"},
		{"SERVICE_HOST", "https://tunnels.layertwo.dev"},
		{"SERVICE_HOST", "tunnels.layertwo.dev:443"},
		{"SERVICE_HOST", "tunnels.layertwo.dev/"},
		{"FRPS_DASHBOARD_URL", "frps:7500"},
		{"FRPS_DASHBOARD_URL", "ftp://frps:7500"},
		{"FRPS_DASHBOARD_URL", "http://"},
		{"FRPS_DASHBOARD_URL", "7500"},
		{"FRPS_DASHBOARD_URL", "http://broker:hunter2@frps:7500"},
		{"FRPS_DASHBOARD_URL", "http://broker@frps:7500"},
		{"FRPS_DASHBOARD_URL", "http://frps:7500?x=1"},
		{"FRPS_DASHBOARD_URL", "http://frps:7500/#x"},
		{"FRPS_DASHBOARD_URL", "http://frps:7500?"},
		{"PLUGIN_SECRET", "short"},
		{"PLUGIN_SECRET", goodSecret[:31]},
		{"PLUGIN_SECRET", goodSecret + "/x"},
		{"PLUGIN_SECRET", goodSecret + "%2f"},
		{"PLUGIN_SECRET", goodSecret + "?x=1"},
		{"PLUGIN_SECRET", goodSecret + " "},
		{"PLUGIN_SECRET", goodSecret + "é"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			vars := allVars()
			vars[tt.name] = tt.value
			_, err := load(vars)
			if err == nil || !strings.Contains(err.Error(), tt.name) {
				t.Fatalf("err = %v, want one naming %s", err, tt.name)
			}
			// What is wrong with a secret must not end up in a log with the secret in it.
			if (tt.name == "PLUGIN_SECRET" || tt.name == "FRPS_DASHBOARD_URL") && strings.Contains(err.Error(), tt.value) {
				t.Errorf("the error repeats the value, which may hold a secret: %v", err)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the error repeats a password: %v", err)
			}
		})
	}
}

func TestLoadConfigAccepts(t *testing.T) {
	tests := []struct {
		name, value string
		check       func(Config) bool
	}{
		{"SITES_DOMAIN", "W.Tunnels.Layertwo.Dev", func(c Config) bool { return c.SitesDomain == "w.tunnels.layertwo.dev" }},
		{"SITES_DOMAIN", "sites", func(c Config) bool { return c.SitesDomain == "sites" }},
		{"SERVICE_HOST", "Tunnels.Layertwo.Dev", func(c Config) bool { return c.ServiceHost == "tunnels.layertwo.dev" }},
		{"DEFAULT_BANDWIDTH_LIMIT", "512KB", func(c Config) bool { return c.BandwidthLimit == "512KB" }},
		{"DEFAULT_BANDWIDTH_LIMIT", "1.5MB", func(c Config) bool { return c.BandwidthLimit == "1.5MB" }},
		{"FRPS_DASHBOARD_URL", "https://frps.example.com:7500/", func(c Config) bool { return c.FrpsDashboardURL == "https://frps.example.com:7500/" }},
		{"PLUGIN_SECRET", strings.Repeat("A-z_9", 8), func(c Config) bool { return c.PluginSecret == strings.Repeat("A-z_9", 8) }},
		{"LOG_LEVEL", "WARN", func(c Config) bool { return c.LogLevel == slog.LevelWarn }},
		{"LISTEN_ADDR", "0.0.0.0:8080", func(c Config) bool { return c.ListenAddr == "0.0.0.0:8080" }},
		{"MAX_TUNNELS_PER_USER", "1", func(c Config) bool { return c.MaxTunnelsPerUser == 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			vars := allVars()
			vars[tt.name] = tt.value
			got, err := load(vars)
			if err != nil || !tt.check(got) {
				t.Errorf("= %+v, %v", got, err)
			}
		})
	}
}

// A secret is never part of an error: a log line about a bad setting must be safe to share.
func TestLoadConfigErrorsHideSecrets(t *testing.T) {
	vars := allVars()
	vars["MAX_TUNNELS_PER_USER"] = "x"
	vars["PLUGIN_SECRET"] = "short-secret-value"
	vars["FRPS_DASHBOARD_PASSWORD"] = "dash-pw-value"
	vars["DATABASE_URL"] = ""
	_, err := load(vars)
	if err == nil {
		t.Fatal("no error")
	}
	for _, secret := range []string{"short-secret-value", "dash-pw-value", "broker:pw"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error contains %q: %v", secret, err)
		}
	}
}
