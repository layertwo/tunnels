// Package frpsapi asks the frps dashboard (API v2) who is online. Every failure is an error, never a
// value that reads as "nobody is online".
package frpsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatedier/frp/server/http/model"

	"github.com/layertwo/tunnels/internal/httpx"
)

// Client talks to one frps dashboard with basic auth.
type Client struct {
	base, user, password string
	http                 *http.Client
}

// New returns a client for the dashboard at baseURL (for example http://frps:7500).
func New(baseURL, user, password, userAgent string) *Client {
	return &Client{
		base:     strings.TrimRight(baseURL, "/"),
		user:     user,
		password: password,
		http:     httpx.Client(userAgent, 10*time.Second),
	}
}

// OnlineRunIDUser reports which user, if any, currently has a connected client with this run ID.
func (c *Client) OnlineRunIDUser(ctx context.Context, runID string) (user string, online bool, err error) {
	if runID == "" { // the dashboard ignores an empty runID filter and lists every client
		return "", false, nil
	}
	page, err := get[model.V2PageResp[model.ClientInfoResp]](ctx, c, "/api/v2/clients", url.Values{
		"runID": {runID}, "status": {"online"}, "pageSize": {"1"},
	})
	if err != nil {
		return "", false, err
	}
	if page.Total == 0 && len(page.Items) == 0 {
		return "", false, nil
	}
	// frps keeps one online record per run ID. Anything else, or a record for another run ID
	// (a filter that was ignored), must not be read as an owner.
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].RunID != runID || !page.Items[0].Online {
		return "", false, fmt.Errorf("frpsapi: unexpected clients answer: total %d, %d items", page.Total, len(page.Items))
	}
	return page.Items[0].User, true, nil
}

// OnlineProxyCount returns how many http proxies the user has online.
func (c *Client) OnlineProxyCount(ctx context.Context, user string) (int, error) {
	if user == "" {
		return 0, errors.New("frpsapi: empty user")
	}
	page, err := get[model.V2PageResp[model.V2ProxyResp]](ctx, c, "/api/v2/proxies", url.Values{
		"type": {"http"}, "user": {user}, "status": {"online"}, "pageSize": {"1"},
	})
	if err != nil {
		return 0, err
	}
	return page.Total, nil
}

// envelope wraps every successful v2 answer: {"code":200,"msg":"success","data":...}.
type envelope[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data *T     `json:"data"`
}

func get[T any](ctx context.Context, c *Client, path string, query url.Values) (T, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path+"?"+query.Encode(), nil)
	if err != nil {
		return zero, fmt.Errorf("frpsapi: build request: %w", err)
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		// A *url.Error repeats the whole URL, and with it the run ID or the handle asked about; the
		// cause is all that is wanted in a log.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return zero, fmt.Errorf("frpsapi: %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("frpsapi: %s answered %d", path, resp.StatusCode)
	}
	var env envelope[T]
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return zero, fmt.Errorf("frpsapi: decode %s: %w", path, err)
	}
	if env.Code != http.StatusOK {
		return zero, fmt.Errorf("frpsapi: %s: code %d: %s", path, env.Code, env.Msg)
	}
	if env.Data == nil { // total 0 and no items would read as "nobody"
		return zero, fmt.Errorf("frpsapi: %s: no data", path)
	}
	return *env.Data, nil
}
