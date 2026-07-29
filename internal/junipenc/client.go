package junipenc

import (
	"context"
	"fmt"
	"net"
)

type Config struct {
	Server   string
	Port     int
	User     string
	Password string
	TUNName  string
}

type Session struct {
	tunName string
	conn    net.Conn
}

func Dial(ctx context.Context, cfg Config) (*Session, string, error) {
	port := cfg.Port
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(cfg.Server, fmt.Sprintf("%d", port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("junipenc: dial: %w", err)
	}
	tunName := cfg.TUNName
	if tunName == "" {
		tunName = "tun-jnc"
	}
	return &Session{tunName: tunName, conn: conn}, tunName, nil
}

func (s *Session) Close() error {
	return s.conn.Close()
}
