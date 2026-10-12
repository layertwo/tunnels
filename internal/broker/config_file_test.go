package broker

import (
	"reflect"
	"strings"
	"testing"
)

// ptr returns a pointer to v, for the pointer fields that distinguish an absent key from an empty one.
func ptr[T any](v T) *T { return &v }

func TestParseFile(t *testing.T) {
	data := []byte(`
[server]
listen_addr = "127.0.0.1:9000"
log_level   = "debug"

[identity]
issuer          = "https://idp.layertwo.dev"
api_resource    = "https://tunnels.layertwo.dev"
creators_group  = "tunnels-creators"
cli_client_id   = "tunnels-cli"
min_cli_version = "0.2.0"
username_claim  = "nickname"
groups_claim    = "roles"

[tunnels]
service_host         = "tunnels.layertwo.dev"
sites_domain         = "w.tunnels.layertwo.dev"
max_tunnels_per_user = 3
bandwidth_limit      = "2MB"
reserved_handles     = ["admin", "root"]

[machines]
enabled          = true
pocket_id_url    = "https://idp.layertwo.dev"
pocket_id_api_id = "api-tunnels"

[metrics]
enabled = true
`)
	got, err := ParseFile(data)
	if err != nil {
		t.Fatal(err)
	}
	want := &FileConfig{
		Server: &serverFile{ListenAddr: ptr("127.0.0.1:9000"), LogLevel: ptr("debug")},
		Identity: &identityFile{
			Issuer: ptr("https://idp.layertwo.dev"), APIResource: ptr("https://tunnels.layertwo.dev"),
			CreatorsGroup: ptr("tunnels-creators"), CLIClientID: ptr("tunnels-cli"),
			MinCLIVersion: ptr("0.2.0"), UsernameClaim: ptr("nickname"), GroupsClaim: ptr("roles"),
		},
		Tunnels: &tunnelsFile{
			ServiceHost: ptr("tunnels.layertwo.dev"), SitesDomain: ptr("w.tunnels.layertwo.dev"),
			MaxTunnelsPerUser: ptr(3), BandwidthLimit: ptr("2MB"),
			ReservedHandles: []string{"admin", "root"},
		},
		Machines: &machinesFile{Enabled: ptr(true), PocketIDURL: ptr("https://idp.layertwo.dev"), PocketIDAPIID: ptr("api-tunnels")},
		Metrics:  &metricsFile{Enabled: ptr(true)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("file =\n%+v\nwant\n%+v", got, want)
	}
}

// An empty file is a valid config: every section is absent (nil), not an error.
func TestParseFileEmpty(t *testing.T) {
	got, err := ParseFile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, &FileConfig{}) {
		t.Errorf("empty file = %+v, want every section nil", got)
	}
}

// Absent differs from present-but-empty, and from a switch set to false.
func TestParseFileAbsentVsEmpty(t *testing.T) {
	got, err := ParseFile([]byte("[server]\n\n[machines]\nenabled = false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Server == nil || got.Server.ListenAddr != nil || got.Server.LogLevel != nil {
		t.Errorf("empty [server] = %+v, want present with no keys set", got.Server)
	}
	if got.Machines == nil || got.Machines.Enabled == nil || *got.Machines.Enabled {
		t.Errorf("machines = %+v, want enabled=false explicitly set", got.Machines)
	}
	if got.Identity != nil || got.Tunnels != nil || got.Metrics != nil {
		t.Errorf("absent sections = %+v, %+v, %+v; want nil", got.Identity, got.Tunnels, got.Metrics)
	}
}

func TestParseFileRejects(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"typo section", "[machine]\nenabled = true\n", "machine"},
		{"unknown key", "[tunnels]\nbogus = 1\n", "bogus"},
		{"unknown key in a known section", "[server]\nlisten = \":1\"\n", "listen"},
		{"malformed toml", "[server\nlisten_addr = \":1\"\n", "config file"},
		{"bad value type", "[tunnels]\nmax_tunnels_per_user = \"many\"\n", "config file"},
		{"secret pocket id key", "[machines]\npocket_id_api_key = \"hunter2\"\n", "pocket_id_api_key"},
		{"secret database url", "[server]\ndatabase_url = \"hunter2\"\n", "database_url"},
		{"secret frps password", "[server]\nfrps_dashboard_password = \"hunter2\"\n", "frps_dashboard_password"},
		{"secret plugin key", "[tunnels]\nplugin_secret = \"hunter2\"\n", "plugin_secret"},
		// A secret is caught even nested where the schema has no section of that name.
		{"secret in an unknown section", "[machine]\npocket_id_api_key = \"hunter2\"\n", "pocket_id_api_key"},
		{"secret in an array of tables", "[[plugins]]\npocket_id_api_key = \"hunter2\"\n", "pocket_id_api_key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFile([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one naming %q", err, tt.want)
			}
			// A config file may be shared: a bad key must not put its value in the error.
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the error repeats the value: %v", err)
			}
		})
	}
}
