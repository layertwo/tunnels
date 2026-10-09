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
	// hostRE matches a lowercase DNS name: no port, no scheme, no trailing dot, no empty label.
	hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	// secretRE is a path element that needs no escaping: the secret is part of the plugin URL.
	secretRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)
)

// LoadConfig reads the settings through getenv. It reports every problem at once, by variable name and
// never with a secret in the text.
func LoadConfig(getenv func(string) string) (Config, error) {
	var errs []error
	bad := func(name, rule string) { errs = append(errs, fmt.Errorf("%s %s", name, rule)) }
	required := func(name string) string {
		v := getenv(name)
		if v == "" {
			bad(name, "is required")
		}
		return v
	}
	optional := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	host := func(name string, v string) string {
		v = strings.ToLower(v)
		if v != "" && !hostRE.MatchString(v) {
			bad(name, "must be a DNS name, without a scheme, a port or a trailing dot")
		}
		return v
	}

	c := Config{
		ServiceHost:   host("SERVICE_HOST", required("SERVICE_HOST")),
		SitesDomain:   host("SITES_DOMAIN", required("SITES_DOMAIN")),
		Issuer:        required("ISSUER"),
		APIResource:   required("API_RESOURCE"),
		CreatorsGroup: required("CREATORS_GROUP"),
		UsernameClaim: optional("USERNAME_CLAIM", "preferred_username"),
		GroupsClaim:   optional("GROUPS_CLAIM", "groups"),
		CLIClientID:   required("CLI_CLIENT_ID"),
		MinCLIVersion: optional("MIN_CLI_VERSION", "0.0.0"),

		DatabaseURL: required("DATABASE_URL"),

		FrpsDashboardURL:      required("FRPS_DASHBOARD_URL"),
		FrpsDashboardUser:     required("FRPS_DASHBOARD_USER"),
		FrpsDashboardPassword: required("FRPS_DASHBOARD_PASSWORD"),
		PluginSecret:          required("PLUGIN_SECRET"),

		BandwidthLimit: optional("DEFAULT_BANDWIDTH_LIMIT", "10MB"),
		ListenAddr:     optional("LISTEN_ADDR", ":8080"),
	}

	if u, err := url.Parse(c.FrpsDashboardURL); c.FrpsDashboardURL != "" && (err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "") {
		bad("FRPS_DASHBOARD_URL", "must be an http or https URL with a host") // the URL may hold credentials: not repeated
	}
	if c.PluginSecret != "" && !secretRE.MatchString(c.PluginSecret) {
		bad("PLUGIN_SECRET", `must be at least 32 characters from A-Z, a-z, 0-9, "-" and "_"`)
	}

	n, err := strconv.Atoi(optional("MAX_TUNNELS_PER_USER", "5"))
	if err != nil || n < 1 {
		bad("MAX_TUNNELS_PER_USER", "must be a whole number, 1 or more")
	}
	c.MaxTunnelsPerUser = n

	// frps ignores a limit it cannot parse, and zero means no limit at all, so refuse both here.
	if q, err := types.NewBandwidthQuantity(c.BandwidthLimit); err != nil || q.Bytes() <= 0 {
		bad("DEFAULT_BANDWIDTH_LIMIT", "must be a positive number of KB or MB, such as 10MB")
	}

	for _, h := range strings.Split(optional("RESERVED_HANDLES", "admin,root,support,security"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			c.Reserved = append(c.Reserved, h)
		}
	}

	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		bad("LISTEN_ADDR", "must be host:port, such as :8080")
	}
	if err := c.LogLevel.UnmarshalText([]byte(optional("LOG_LEVEL", "info"))); err != nil {
		bad("LOG_LEVEL", "must be debug, info, warn or error")
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}
