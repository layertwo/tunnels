package names

import (
	"strings"
	"testing"
)

func TestHandleFromUsername(t *testing.T) {
	reserved := []string{"admin", "root", "support", "security"}
	const rule = "use 2 to 20 letters and digits"
	tests := []struct {
		username string
		want     string
		errHas   string // "" when accepted, else text the error shown to the user must contain
	}{
		{"Alice", "alice", ""},
		{"al", "al", ""},
		{strings.Repeat("a", 20), strings.Repeat("a", 20), ""},
		{"a", "", rule},
		{strings.Repeat("a", 21), "", rule},
		{"", "", rule},
		{"alice_b", "", rule},
		{"alice.b", "", rule},
		{"alice@x", "", rule},
		{"alice-b", "", rule},
		{"\u212Aevin", "", rule}, // Kelvin sign: strings.ToLower would turn it into "kevin"
		{"ünal", "", rule},
		{"alice\n", "", rule}, // a regexp $ that tolerates a trailing newline would accept this
		{"Admin", "", "reserved"},
		{"ROOT", "", "reserved"},
	}
	for _, tt := range tests {
		got, err := HandleFromUsername(tt.username, reserved)
		switch {
		case tt.errHas == "" && err != nil:
			t.Errorf("HandleFromUsername(%q) failed: %v", tt.username, err)
		case tt.errHas != "" && (err == nil || !strings.Contains(err.Error(), tt.errHas)):
			t.Errorf("HandleFromUsername(%q) error = %v, want one containing %q", tt.username, err, tt.errHas)
		case got != tt.want:
			t.Errorf("HandleFromUsername(%q) = %q, want %q", tt.username, got, tt.want)
		}
	}

	// the configured list may be written in any case
	if _, err := HandleFromUsername("admin", []string{"Admin"}); err == nil {
		t.Error(`reserved entry "Admin" did not block "admin"`)
	}
}

func TestValidTunnelName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"blog", true}, {"a", true}, {"a-b", true}, {"a--b", true}, {strings.Repeat("a", 42), true},
		{"default", false}, {"", false}, {"-a", false}, {"a-", false}, {"Blog", false}, {"a_b", false},
		{strings.Repeat("a", 43), false}, {"blog\n", false},
	}
	for _, tt := range tests {
		if got := ValidTunnelName(tt.name); got != tt.want {
			t.Errorf("ValidTunnelName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestLabel(t *testing.T) {
	tests := []struct{ handle, tunnel, label string }{
		{"alice", "", "alice"},
		{"alice", "default", "alice"},
		{"alice", "blog", "alice-blog"},
	}
	for _, tt := range tests {
		if got := Label(tt.handle, tt.tunnel); got != tt.label {
			t.Errorf("Label(%q, %q) = %q, want %q", tt.handle, tt.tunnel, got, tt.label)
		}
	}
}

func TestParseLabel(t *testing.T) {
	h20 := strings.Repeat("a", 20)
	n42 := strings.Repeat("b", 42)
	tests := []struct {
		label, handle, tunnel string
		ok                    bool
	}{
		{"alice", "alice", "", true},
		{"alice-blog", "alice", "blog", true},
		{"alice-a-b", "alice", "a-b", true},
		{h20 + "-" + n42, h20, n42, true}, // 63 characters, the DNS label limit
		{"alice-", "", "", false},
		{"-blog", "", "", false},
		{"alice-default", "", "", false},
		{"Alice", "", "", false},
		{"a", "", "", false},
		{"alice--x", "", "", false},
		{"alice-Blog", "", "", false},
		{strings.Repeat("a", 64), "", "", false},
		{h20 + "-" + n42 + "b", "", "", false}, // 64 characters
		{"", "", "", false},
	}
	for _, tt := range tests {
		handle, tunnel, ok := ParseLabel(tt.label)
		if handle != tt.handle || tunnel != tt.tunnel || ok != tt.ok {
			t.Errorf("ParseLabel(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.label, handle, tunnel, ok, tt.handle, tt.tunnel, tt.ok)
		}
	}
}

func TestSiteLabel(t *testing.T) {
	const domain = "w.tunnels.layertwo.dev"
	tests := []struct {
		host, label string
		ok          bool
	}{
		{"alice-blog.w.tunnels.layertwo.dev", "alice-blog", true},
		{"Alice.W.Tunnels.Layertwo.Dev", "alice", true},
		{"alice.w.tunnels.layertwo.dev:443", "", false},
		{"alice.w.tunnels.layertwo.dev.", "", false},
		{"x.alice.w.tunnels.layertwo.dev", "", false},
		{"w.tunnels.layertwo.dev", "", false},
		{"alice.tunnels.layertwo.dev", "", false},
		{"alice.w.tunnels.layertwo.dev.evil.com", "", false},
		{"a.com, b.com", "", false},
		{"", "", false},
		{".w.tunnels.layertwo.dev", "", false},              // empty label
		{"evil, alice.w.tunnels.layertwo.dev", "", false},   // a list whose last entry is ours
		{"alice-default.w.tunnels.layertwo.dev", "", false}, // not a label Label() ever produces
		{"\u212Aevin.w.tunnels.layertwo.dev", "", false},    // Kelvin sign must not become "kevin"
		{"alice.w.tunnels.layertwo.dev\n", "", false},       // trailing newline
	}
	// the configured domain may be written in any case too
	for _, d := range []string{domain, strings.ToUpper(domain)} {
		for _, tt := range tests {
			label, ok := SiteLabel(tt.host, d)
			if label != tt.label || ok != tt.ok {
				t.Errorf("SiteLabel(%q, %q) = (%q, %v), want (%q, %v)", tt.host, d, label, ok, tt.label, tt.ok)
			}
		}
	}
}

// ValidHandle is what a stored handle must satisfy before a label is built from it: Label(handle, x)
// has to parse back to this owner, so no dash, no capitals and nothing HandleFromUsername refuses.
func TestValidHandle(t *testing.T) {
	tests := []struct {
		handle string
		want   bool
	}{
		{"alice", true},
		{"al", true},
		{"a1", true},
		{strings.Repeat("a", 20), true},
		{"", false},
		{"a", false},
		{strings.Repeat("a", 21), false},
		{"Alice", false},
		{"alice-b", false}, // Label("alice-b", "c") would parse back as owner "alice"
		{"alice_b", false},
		{"alice.b", false},
		{"alice b", false},
		{"alice\n", false},
		{"\u212Aevin", false},
		{"ünal", false},
	}
	for _, tt := range tests {
		if got := ValidHandle(tt.handle); got != tt.want {
			t.Errorf("ValidHandle(%q) = %v, want %v", tt.handle, got, tt.want)
		}
	}
}
