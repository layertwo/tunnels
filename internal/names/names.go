// Package names holds the handle, tunnel name and site label rules that the
// broker and the CLI share.
package names

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Default is the name of the tunnel used when none is given. It is reserved:
// no tunnel can be given this name explicitly.
const Default = "default"

var (
	// usernameRE is matched against the original username, before lowercasing.
	usernameRE = regexp.MustCompile(`^[A-Za-z0-9]{2,20}$`)
	// handleRE must accept exactly what usernameRE accepts once lowercased.
	handleRE = regexp.MustCompile(`^[a-z0-9]{2,20}$`)
	// 1 to 42 characters, so that handle (20) + "-" + name (42) fits a 63 character DNS label.
	tunnelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
)

// HandleFromUsername returns the handle for a Pocket ID username: the lowercased
// username, if it is 2 to 20 ASCII letters and digits and not in reserved
// (compared case-insensitively). The error text is shown to the user.
func HandleFromUsername(username string, reserved []string) (string, error) {
	// Check the original: strings.ToLower maps U+212A (Kelvin sign) to "k".
	if !usernameRE.MatchString(username) {
		return "", fmt.Errorf("username %q cannot be a tunnel handle: use 2 to 20 letters and digits", username)
	}
	handle := strings.ToLower(username)
	if slices.ContainsFunc(reserved, func(r string) bool { return strings.EqualFold(r, handle) }) {
		return "", fmt.Errorf("handle %q is reserved", handle)
	}
	return handle, nil
}

// ValidHandle reports whether handle is one HandleFromUsername could have made: 2 to 20 lowercase
// letters and digits.
func ValidHandle(handle string) bool { return handleRE.MatchString(handle) }

// ValidTunnelName reports whether name is a tunnel name: 1 to 42 lowercase
// letters, digits and inner dashes. Default and "" are not names.
func ValidTunnelName(name string) bool {
	return name != Default && tunnelRE.MatchString(name)
}

// Label returns the site label of a tunnel: handle for the default tunnel
// ("" or Default), else handle-tunnel.
func Label(handle, tunnel string) string {
	if tunnel == "" || tunnel == Default {
		return handle
	}
	return handle + "-" + tunnel
}

// ProxyName returns the frp proxy name of a tunnel: handle.tunnel, with Default
// standing in for "".
func ProxyName(handle, tunnel string) string {
	if tunnel == "" {
		tunnel = Default
	}
	return handle + "." + tunnel
}

// ParseLabel splits a site label made by Label. The owner is the text before
// the first dash; tunnel is "" for the default tunnel.
func ParseLabel(label string) (handle, tunnel string, ok bool) {
	handle, tunnel, hasTunnel := strings.Cut(label, "-")
	if !handleRE.MatchString(handle) || (hasTunnel && !ValidTunnelName(tunnel)) {
		return "", "", false
	}
	return handle, tunnel, true
}

// SiteLabel returns the lowercased site label of host, an X-Forwarded-Host
// value that must be exactly <label>.<sitesDomain> (any case) with a label that
// ParseLabel accepts. A port, a trailing dot, an extra label, a list of hosts
// or a non-ASCII byte is refused. sitesDomain is the configured, non-empty domain.
func SiteLabel(host, sitesDomain string) (label string, ok bool) {
	// Same reason as in HandleFromUsername: refuse non-ASCII before lowercasing.
	if strings.ContainsFunc(host, func(r rune) bool { return r > unicode.MaxASCII }) {
		return "", false
	}
	label, ok = strings.CutSuffix(strings.ToLower(host), "."+strings.ToLower(sitesDomain))
	if _, _, valid := ParseLabel(label); !ok || !valid {
		return "", false
	}
	return label, true
}
