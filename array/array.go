package array

import (
	"context"
	"fmt"
	"strconv"

	"github.com/xen0bit/veepin/client"
)

const (
	OptServer   = "server"
	OptPort     = "port"
	OptUser     = "user"
	OptPassword = "password"
	OptTUN      = "tun"
)

type Config struct {
	Server   string
	Port     int
	User     string
	Password string
	TUNName  string
}

func Dial(ctx context.Context, cfg Config) (client.Session, client.Result, error) {
	res := client.Result{
		TUNName:    cfg.TUNName,
		AssignedIP: nil,
		Gateway:    nil,
		MTU:        client.DefaultTunnelMTU,
	}
	if res.TUNName == "" {
		res.TUNName = "tun-array"
	}
	sess := &session{}
	return sess, res, nil
}

type session struct{}

func (s *session) Wait(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (s *session) Close() error                   { return nil }

type dialer struct{ cfg Config }

func (d dialer) Dial(ctx context.Context) (client.Session, client.Result, error) {
	return Dial(ctx, d.cfg)
}

func parseOptions(opts map[string]string) (client.Dialer, error) {
	cfg := Config{
		Server:   opts[OptServer],
		User:     opts[OptUser],
		Password: opts[OptPassword],
		TUNName:  opts[OptTUN],
	}
	if p := opts[OptPort]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("array: bad %s %q: %w", OptPort, p, err)
		}
		cfg.Port = n
	}
	return dialer{cfg: cfg}, nil
}

func init() {
	client.Register("array", parseOptions)
}
