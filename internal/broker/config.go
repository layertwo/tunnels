package broker

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/fatedier/frp/pkg/config/types"
)

// Config is the broker's settings, one field per environment variable.
type Config struct {
	ServiceHost string // tunnels.layertwo.dev, where the CLI connects
	SitesDomain string // w.tunnels.layertwo.dev, under which every site lives

	Issuer        string // the OIDC provider
	APIResource   string // the audience of access tokens meant for the broker
	CreatorsGroup string // the group whose members may publish
	UsernameClaim string
	GroupsClaim   string
	CLIClientID   string
	MinCLIVersion string

	DatabaseURL string

	PocketIDURL    string // the Pocket ID instance whose admin API mints a machine's client
	PocketIDAPIKey string // the admin API key; never logged
	PocketIDAPIID  string // the Tunnels API a machine's client is granted access to

	// MachinesEnabled and MetricsEnabled are on only when the file has the feature's section and it is
	// not enabled = false. With no file they keep the environment-only behaviour of before the file.
	MachinesEnabled bool
	MetricsEnabled  bool

	// SSHDomain is the one host every SSH tunnel is published at, without a scheme, a port or a
	// trailing dot. It is empty when the feature is off, and the bootstrap document then omits it.
	SSHDomain string

	FrpsDashboardURL      string
	FrpsDashboardUser     string
	FrpsDashboardPassword string
	PluginSecret          string

	MaxTunnelsPerUser int
	BandwidthLimit    string
	Reserved          []string

	ListenAddr string
	LogLevel   slog.Level
}

var (
	// hostRE matches a DNS name: no port, no scheme, no trailing dot, no empty label. It is applied to
	// the value as given, before lowercasing, because strings.ToLower turns U+212A into "k".
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	// secretRE is a path element that needs no escaping: the secret is part of the plugin URL.
	secretRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)
)

// badDashboardURL reports whether raw is set but is not a bare http(s) URL: a scheme, a host and
// nothing else, so no credentials, query or fragment could end up in an error or a log.
func badDashboardURL(raw string) bool {
	u, err := url.Parse(raw)
	return raw != "" && (err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery)
}

// sectionOn reports whether a feature section leaves its feature on: an absent key means on, and only
// an explicit `enabled = false` turns it off.
func sectionOn(enabled *bool) bool { return enabled == nil || *enabled }

// pick returns the environment value when it is set, else the file's value when the key is present (a
// nil pointer is an absent key), else the built-in default. The environment always wins, so a
// container or a per-environment deploy can override a file setting.
func pick(getenv func(string) string, env string, file *string, def string) string {
	if v := getenv(env); v != "" {
		return v
	}
	if file != nil {
		return *file
	}
	return def
}

// LoadConfig merges the configuration file (which may be nil) with the environment, the environment
// winning, and validates the result. It reports every problem at once, by variable name and never with
// a secret in the text. A feature is on only when the file has its section and it is not enabled =
// false; a set enabling variable with no section, or an enabled feature missing an input, is an error.
func LoadConfig(getenv func(string) string, file *FileConfig) (Config, error) {
	var errs []error
	bad := func(name, rule string) { errs = append(errs, fmt.Errorf("%s %s", name, rule)) }
	required := func(name, v string) string {
		if v == "" {
			bad(name, "is required")
		}
		return v
	}
	host := func(name string, v string) string {
		if v != "" && !hostRE.MatchString(v) {
			bad(name, "must be a DNS name, without a scheme, a port or a trailing dot")
		}
		return strings.ToLower(v)
	}

	// A section is nil when the file or the section is absent; a zero section then has every key nil,
	// so each setting below reads as "environment, else file, else default".
	var (
		server   serverFile
		identity identityFile
		tunnels  tunnelsFile
		machines machinesFile
		ssh      sshFile
	)
	if file != nil {
		if file.Server != nil {
			server = *file.Server
		}
		if file.Identity != nil {
			identity = *file.Identity
		}
		if file.Tunnels != nil {
			tunnels = *file.Tunnels
		}
		if file.Machines != nil {
			machines = *file.Machines
		}
		if file.SSH != nil {
			ssh = *file.SSH
		}
	}
	c := Config{
		ServiceHost:   host("SERVICE_HOST", required("SERVICE_HOST", pick(getenv, "SERVICE_HOST", tunnels.ServiceHost, ""))),
		SitesDomain:   host("SITES_DOMAIN", required("SITES_DOMAIN", pick(getenv, "SITES_DOMAIN", tunnels.SitesDomain, ""))),
		Issuer:        required("ISSUER", pick(getenv, "ISSUER", identity.Issuer, "")),
		APIResource:   required("API_RESOURCE", pick(getenv, "API_RESOURCE", identity.APIResource, "")),
		CreatorsGroup: required("CREATORS_GROUP", pick(getenv, "CREATORS_GROUP", identity.CreatorsGroup, "")),
		UsernameClaim: pick(getenv, "USERNAME_CLAIM", identity.UsernameClaim, "preferred_username"),
		GroupsClaim:   pick(getenv, "GROUPS_CLAIM", identity.GroupsClaim, "groups"),
		CLIClientID:   required("CLI_CLIENT_ID", pick(getenv, "CLI_CLIENT_ID", identity.CLIClientID, "")),
		MinCLIVersion: pick(getenv, "MIN_CLI_VERSION", identity.MinCLIVersion, "0.0.0"),

		// The database URL is a secret: the environment only, never the file.
		DatabaseURL: required("DATABASE_URL", getenv("DATABASE_URL")),

		// The machine-admin settings. The API key is a secret; the URL and the API id may come from the
		// file's [machines] section. Whether the feature is on is decided below.
		PocketIDURL:    pick(getenv, "POCKET_ID_URL", machines.PocketIDURL, ""),
		PocketIDAPIKey: getenv("POCKET_ID_API_KEY"),
		PocketIDAPIID:  pick(getenv, "POCKET_ID_API_ID", machines.PocketIDAPIID, ""),

		FrpsDashboardURL:      required("FRPS_DASHBOARD_URL", getenv("FRPS_DASHBOARD_URL")),
		FrpsDashboardUser:     required("FRPS_DASHBOARD_USER", getenv("FRPS_DASHBOARD_USER")),
		FrpsDashboardPassword: required("FRPS_DASHBOARD_PASSWORD", getenv("FRPS_DASHBOARD_PASSWORD")),
		PluginSecret:          required("PLUGIN_SECRET", getenv("PLUGIN_SECRET")),

		BandwidthLimit: pick(getenv, "DEFAULT_BANDWIDTH_LIMIT", tunnels.BandwidthLimit, "10MB"),
		ListenAddr:     pick(getenv, "LISTEN_ADDR", server.ListenAddr, ":8080"),
	}

	// A feature is on iff the file has its section and enabled is not false. With no file at all the
	// broker runs from the environment, exactly as before the file existed.
	switch {
	case file == nil:
		c.MachinesEnabled = c.PocketIDURL != ""
	case file.Machines == nil:
		// POCKET_ID_URL is the non-secret variable that turns machines on. With no section a typo or a
		// half-migration must be loud, naming both, rather than silently disabling the feature. A
		// secret alone never enables, so it needs no section.
		if c.PocketIDURL != "" {
			bad("POCKET_ID_URL", "is set but the config file has no [machines] section; add one or unset POCKET_ID_URL")
		}
	default:
		c.MachinesEnabled = sectionOn(machines.Enabled)
	}
	// With no file at all, metrics keep today's behaviour: always mounted. A file turns the feature on
	// only with a [metrics] section that is not enabled = false.
	c.MetricsEnabled = file == nil || (file.Metrics != nil && sectionOn(file.Metrics.Enabled))

	// The SSH feature follows the same switch as machines. With no file it is on exactly when
	// SSH_DOMAIN is set, the behaviour before the file existed; with a file it is on exactly when the
	// [ssh] section is present and not enabled = false. SSH_DOMAIN turns the feature on, so with no
	// section it is a half-migration a typo could cause: loud, naming both. A disabled section's
	// domain is ignored, so a malformed one is not a startup error, and nothing is resolved.
	sshOn := false
	switch {
	case file == nil:
		sshOn = getenv("SSH_DOMAIN") != ""
	case file.SSH == nil:
		if getenv("SSH_DOMAIN") != "" {
			bad("SSH_DOMAIN", "is set but the config file has no [ssh] section; add one or unset SSH_DOMAIN")
		}
	default:
		sshOn = sectionOn(ssh.Enabled)
	}
	if sshOn {
		c.SSHDomain = host("SSH_DOMAIN", required("SSH_DOMAIN", pick(getenv, "SSH_DOMAIN", ssh.Domain, "")))
	}
	// decide checks the SSH host before the sites, so an SSH host equal to, or under, SITES_DOMAIN
	// would shadow a site of that name: a site so named could never be reached. Refuse the pair.
	if c.SSHDomain != "" && (c.SSHDomain == c.SitesDomain || strings.HasSuffix(c.SSHDomain, "."+c.SitesDomain)) {
		bad("SSH_DOMAIN", "must not be SITES_DOMAIN or under it")
	}

	// The credentials are separate variables; none in the URL, which would also end up in errors and logs.
	if badDashboardURL(c.FrpsDashboardURL) {
		bad("FRPS_DASHBOARD_URL", "must be an http or https URL with a host and nothing else: no credentials, query or fragment") // not repeated: it may hold a password
	}
	// A disabled [machines] ignores its other keys, so a malformed URL is not a startup error. The URL
	// is still validated whenever the feature is on, from either source.
	if c.MachinesEnabled && badDashboardURL(c.PocketIDURL) {
		bad("POCKET_ID_URL", "must be an http or https URL with a host and nothing else: no credentials, query or fragment")
	}
	if file == nil {
		// With no file, the machine-admin config is the old all-or-nothing environment group: a half-set
		// one is a mistake, not "machines off".
		if on := c.PocketIDURL != ""; on != (c.PocketIDAPIKey != "") || on != (c.PocketIDAPIID != "") {
			bad("POCKET_ID_URL", "must be set with POCKET_ID_API_KEY and POCKET_ID_API_ID, or all three left unset")
		}
	} else if c.MachinesEnabled {
		// An enabled feature is missing a required input: name the environment variable that supplies it.
		for _, in := range []struct{ name, v string }{
			{"POCKET_ID_URL", c.PocketIDURL},
			{"POCKET_ID_API_KEY", c.PocketIDAPIKey},
			{"POCKET_ID_API_ID", c.PocketIDAPIID},
		} {
			if in.v == "" {
				bad(in.name, "is required when [machines] is enabled")
			}
		}
	}
	if c.PluginSecret != "" && !secretRE.MatchString(c.PluginSecret) {
		bad("PLUGIN_SECRET", `must be at least 32 characters from A-Z, a-z, 0-9, "-" and "_"`)
	}

	maxRaw := getenv("MAX_TUNNELS_PER_USER")
	if maxRaw == "" && tunnels.MaxTunnelsPerUser != nil {
		maxRaw = strconv.Itoa(*tunnels.MaxTunnelsPerUser)
	}
	if maxRaw == "" {
		maxRaw = "5"
	}
	n, err := strconv.Atoi(maxRaw)
	if err != nil || n < 1 {
		bad("MAX_TUNNELS_PER_USER", "must be a whole number, 1 or more")
	}
	c.MaxTunnelsPerUser = n

	// frps ignores a limit it cannot parse, and zero means no limit at all, so refuse both here.
	if q, err := types.NewBandwidthQuantity(c.BandwidthLimit); err != nil || q.Bytes() <= 0 {
		bad("DEFAULT_BANDWIDTH_LIMIT", "must be a positive number of KB or MB, such as 10MB")
	}

	var handles []string
	switch rh := getenv("RESERVED_HANDLES"); {
	case rh != "":
		handles = strings.Split(rh, ",")
	case tunnels.ReservedHandles != nil:
		handles = tunnels.ReservedHandles
	default:
		handles = []string{"admin", "root", "support", "security"}
	}
	for _, h := range handles {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			c.Reserved = append(c.Reserved, h)
		}
	}

	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		bad("LISTEN_ADDR", "must be host:port, such as :8080")
	}
	if err := c.LogLevel.UnmarshalText([]byte(pick(getenv, "LOG_LEVEL", server.LogLevel, "info"))); err != nil {
		bad("LOG_LEVEL", "must be debug, info, warn or error")
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}
