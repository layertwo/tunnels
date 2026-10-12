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
		"POCKET_ID_URL":           "https://idp.layertwo.dev",
		"POCKET_ID_API_KEY":       "pocket-admin-key",
		"POCKET_ID_API_ID":        "api-tunnels",
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
	return loadFile(vars, nil)
}

// loadFile loads with a config file, or nil for the environment-only behaviour of before the file.
func loadFile(vars map[string]string, file *FileConfig) (Config, error) {
	return LoadConfig(func(k string) string { return vars[k] }, file)
}

var required = []string{
	"SERVICE_HOST", "SITES_DOMAIN", "ISSUER", "API_RESOURCE", "CREATORS_GROUP", "CLI_CLIENT_ID",
	"DATABASE_URL",
	"FRPS_DASHBOARD_URL", "FRPS_DASHBOARD_USER", "FRPS_DASHBOARD_PASSWORD", "PLUGIN_SECRET",
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
		DatabaseURL: "postgres://broker:pw@db:5432/tunnels",
		PocketIDURL: "https://idp.layertwo.dev", PocketIDAPIKey: "pocket-admin-key", PocketIDAPIID: "api-tunnels",
		MachinesEnabled: true, MetricsEnabled: true,
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

// MACHINE_CLIENTS is gone: a machine's mapping lives in the machines table, so an environment that
// still sets the variable must load unchanged and must not fail.
func TestLoadConfigIgnoresMachineClients(t *testing.T) {
	want, err := load(allVars())
	if err != nil {
		t.Fatal(err)
	}
	vars := allVars()
	vars["MACHINE_CLIENTS"] = "id1=Alice,id2=BOX,junk"
	got, err := load(vars)
	if err != nil {
		t.Fatalf("a stale MACHINE_CLIENTS failed the load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config with MACHINE_CLIENTS =\n%+v\nwant\n%+v", got, want)
	}
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

// The machine-admin config is optional and all-or-nothing: set none and the broker serves people only;
// a half-set one is a mistake, not "machines off".
func TestLoadConfigMachineAdminIsOptional(t *testing.T) {
	vars := allVars()
	for _, k := range []string{"POCKET_ID_URL", "POCKET_ID_API_KEY", "POCKET_ID_API_ID"} {
		delete(vars, k)
	}
	got, err := load(vars)
	if err != nil || got.PocketIDURL != "" || got.PocketIDAPIKey != "" || got.PocketIDAPIID != "" {
		t.Fatalf("without the machine admin config: %+v, %v; want no error and no values", got, err)
	}

	for _, missing := range []string{"POCKET_ID_URL", "POCKET_ID_API_KEY", "POCKET_ID_API_ID"} {
		t.Run("without "+missing, func(t *testing.T) {
			vars := allVars()
			delete(vars, missing)
			if _, err := load(vars); err == nil || !strings.Contains(err.Error(), "POCKET_ID_") {
				t.Errorf("without %s: err = %v, want one naming the machine config", missing, err)
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
		{"POCKET_ID_URL", "idp:8080"},
		{"POCKET_ID_URL", "ftp://idp.example.com"},
		{"POCKET_ID_URL", "http://"},
		{"POCKET_ID_URL", "http://pocket:hunter2@idp.example.com"},
		{"POCKET_ID_URL", "https://idp.example.com?x=1"},
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
			if (tt.name == "PLUGIN_SECRET" || tt.name == "FRPS_DASHBOARD_URL" || tt.name == "POCKET_ID_URL") && strings.Contains(err.Error(), tt.value) {
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
	vars["POCKET_ID_API_KEY"] = "pocket-key-value"
	vars["DATABASE_URL"] = ""
	_, err := load(vars)
	if err == nil {
		t.Fatal("no error")
	}
	for _, secret := range []string{"short-secret-value", "dash-pw-value", "pocket-key-value", "broker:pw"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error contains %q: %v", secret, err)
		}
	}
}

// secretsOnly is the environment the file cannot supply: every secret and the frps settings that are
// not in the schema. It is enough to start once the file carries the rest of the plumbing.
func secretsOnly() map[string]string {
	return map[string]string{
		"DATABASE_URL":            "postgres://broker:pw@db:5432/tunnels",
		"FRPS_DASHBOARD_URL":      "http://frps.tunnels.svc:7500",
		"FRPS_DASHBOARD_USER":     "broker",
		"FRPS_DASHBOARD_PASSWORD": "dash-pw",
		"PLUGIN_SECRET":           goodSecret,
	}
}

// A file supplies the plumbing and the always-on tunnel settings; the environment supplies the secrets.
func TestLoadConfigFromFile(t *testing.T) {
	file := &FileConfig{
		Server: &serverFile{ListenAddr: ptr("127.0.0.1:9000"), LogLevel: ptr("debug")},
		Identity: &identityFile{
			Issuer: ptr("https://idp.layertwo.dev"), APIResource: ptr("https://tunnels.layertwo.dev"),
			CreatorsGroup: ptr("tunnels-creators"), CLIClientID: ptr("tunnels-cli"),
			MinCLIVersion: ptr("0.2.0"), UsernameClaim: ptr("nickname"), GroupsClaim: ptr("roles"),
		},
		Tunnels: &tunnelsFile{
			ServiceHost: ptr("tunnels.layertwo.dev"), SitesDomain: ptr("w.tunnels.layertwo.dev"),
			MaxTunnelsPerUser: ptr(3), BandwidthLimit: ptr("2MB"),
			ReservedHandles: []string{"admin", "Root", ""},
		},
	}
	got, err := loadFile(secretsOnly(), file)
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
		Reserved: []string{"admin", "root"}, ListenAddr: "127.0.0.1:9000", LogLevel: slog.LevelDebug,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config =\n%+v\nwant\n%+v", got, want)
	}
}

// The "a file is the whole config" rule still lets the environment override any value, so a container
// or a per-environment deploy works: the variable wins over the file's key.
func TestLoadConfigEnvironmentOverridesFile(t *testing.T) {
	vars := allVars()
	vars["POCKET_ID_URL"] = "https://env.example.com"
	vars["LISTEN_ADDR"] = "127.0.0.1:9001"
	file := &FileConfig{
		Server:  &serverFile{ListenAddr: ptr("10.0.0.1:9000")},
		Metrics: &metricsFile{},
		Machines: &machinesFile{
			Enabled: ptr(true), PocketIDURL: ptr("https://file.example.com"), PocketIDAPIID: ptr("api-file"),
		},
	}
	got, err := loadFile(vars, file)
	if err != nil {
		t.Fatal(err)
	}
	// The environment wins over a differing file value for both a section setting and a machine one;
	// the file fills a value the environment leaves unset.
	if got.PocketIDURL != "https://env.example.com" || got.PocketIDAPIID != "api-tunnels" || got.ListenAddr != "127.0.0.1:9001" {
		t.Errorf("merged = %+v, want the environment to win and the file to fill the rest", got)
	}
}

// A non-secret variable that turns a feature on, with no section, is a half-migration a typo could
// cause; it must be loud, naming both the variable and the missing section.
func TestLoadConfigEnablingVariableWithoutSection(t *testing.T) {
	_, err := loadFile(allVars(), &FileConfig{Server: &serverFile{}})
	if err == nil || !strings.Contains(err.Error(), "POCKET_ID_URL") || !strings.Contains(err.Error(), "[machines]") {
		t.Fatalf("err = %v, want one naming POCKET_ID_URL and [machines]", err)
	}
}

// A secret never enables a feature: set the machine API key and id with no [machines] section and the
// feature stays off, with no error, so a mounted secret cannot stop machines being turned off.
func TestLoadConfigSecretDoesNotEnableMachines(t *testing.T) {
	vars := allVars()
	delete(vars, "POCKET_ID_URL")
	got, err := loadFile(vars, &FileConfig{Server: &serverFile{}})
	if err != nil {
		t.Fatalf("a secret alone must not be an error: %v", err)
	}
	if got.MachinesEnabled {
		t.Errorf("machines = %+v, want off", got)
	}
}

// enabled = false wins over the environment: the feature is off and nothing else is validated.
func TestLoadConfigMachinesDisabledWins(t *testing.T) {
	got, err := loadFile(allVars(), &FileConfig{Machines: &machinesFile{Enabled: ptr(false)}})
	if err != nil {
		t.Fatalf("a disabled [machines] must not error: %v", err)
	}
	if got.MachinesEnabled {
		t.Errorf("machines = %+v, want off", got)
	}
}

// A disabled section's other keys are ignored, so a malformed POCKET_ID_URL set alongside enabled =
// false is not a startup error: the URL is only validated when the feature is on.
func TestLoadConfigMachinesDisabledSkipsURLValidation(t *testing.T) {
	vars := allVars()
	vars["POCKET_ID_URL"] = "idp:8080"
	got, err := loadFile(vars, &FileConfig{Machines: &machinesFile{Enabled: ptr(false)}})
	if err != nil {
		t.Fatalf("a disabled [machines] must not validate its URL: %v", err)
	}
	if got.MachinesEnabled {
		t.Errorf("machines = %+v, want off", got)
	}
}

// A section with no enabled key is on: enabled != false.
func TestLoadConfigMachinesEnabledByPresence(t *testing.T) {
	got, err := loadFile(allVars(), &FileConfig{Machines: &machinesFile{PocketIDURL: ptr("https://file.example.com")}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.MachinesEnabled {
		t.Errorf("machines = %+v, want on", got)
	}
}

// An enabled feature is missing an input the environment must supply: name the variable, never a value.
func TestLoadConfigMachinesRequiresItsInputs(t *testing.T) {
	for _, tt := range []struct{ name, missing string }{
		{"url", "POCKET_ID_URL"},
		{"key", "POCKET_ID_API_KEY"},
		{"id", "POCKET_ID_API_ID"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			vars := allVars()
			delete(vars, tt.missing)
			// The section is on; the missing input has to come from the environment, since the file
			// has no key for a secret and the others are left to the environment here.
			file := &FileConfig{Machines: &machinesFile{Enabled: ptr(true)}}
			_, err := loadFile(vars, file)
			if err == nil || !strings.Contains(err.Error(), tt.missing) {
				t.Fatalf("without %s: err = %v, want one naming it", tt.missing, err)
			}
		})
	}
}

// With a file, metrics are on exactly when its section exists and enabled is not false. With no file
// at all they keep today's behaviour: always on.
func TestLoadConfigMetricsEnabled(t *testing.T) {
	vars := allVars()
	for _, k := range []string{"POCKET_ID_URL", "POCKET_ID_API_KEY", "POCKET_ID_API_ID"} {
		delete(vars, k)
	}
	tests := []struct {
		name string
		file *FileConfig
		want bool
	}{
		{"nil file", nil, true},
		{"no [metrics] section", &FileConfig{Server: &serverFile{}}, false},
		{"empty [metrics]", &FileConfig{Metrics: &metricsFile{}}, true},
		{"[metrics] enabled=true", &FileConfig{Metrics: &metricsFile{Enabled: ptr(true)}}, true},
		{"[metrics] enabled=false", &FileConfig{Metrics: &metricsFile{Enabled: ptr(false)}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The nil-file case has the machine config set, which a file with no [machines] rejects.
			v := vars
			if tt.file == nil {
				v = allVars()
			}
			got, err := loadFile(v, tt.file)
			if err != nil || got.MetricsEnabled != tt.want {
				t.Errorf("metrics = %v, %v; want %v", got.MetricsEnabled, err, tt.want)
			}
		})
	}
}

// With a file and no [machines] section the machine endpoints are off and the machine config is absent.
func TestLoadConfigMachinesOffWithoutSection(t *testing.T) {
	vars := allVars()
	for _, k := range []string{"POCKET_ID_URL", "POCKET_ID_API_KEY", "POCKET_ID_API_ID"} {
		delete(vars, k)
	}
	got, err := loadFile(vars, &FileConfig{Server: &serverFile{}})
	if err != nil {
		t.Fatal(err)
	}
	if got.MachinesEnabled || got.PocketIDURL != "" || got.PocketIDAPIKey != "" || got.PocketIDAPIID != "" {
		t.Errorf("machines = %+v, want off with no config", got)
	}
}
