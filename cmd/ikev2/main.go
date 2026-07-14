// Command ikev2 is a userspace IKEv2 VPN client. It connects to an IKEv2 server
// (this project's ikev2d, or any RFC 7296 responder that accepts PSK or
// EAP-MSCHAPv2), obtains an internal address via configuration mode, brings up a
// local TUN interface, installs routes, and runs a userspace ESP-in-UDP data
// path so the host's traffic flows through the tunnel.
//
// Creating a TUN device and editing the routing table require CAP_NET_ADMIN:
//
//	go build -o ikev2 ./cmd/ikev2
//	sudo ./ikev2 -server vpn.example.com -psk 'secret' -id client.example
//
// Authentication is PSK by default; pass -user/-pass to use EAP-MSCHAPv2
// (the server still authenticates itself with the PSK).
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/ikev2-go/internal/dataplane"
	"github.com/example/ikev2-go/internal/ike"
)

func main() {
	var (
		server   = flag.String("server", "", "VPN server host or IP (required)")
		port     = flag.Int("port", 500, "server IKE port")
		psk      = flag.String("psk", "", "pre-shared key (required)")
		idStr    = flag.String("id", "", "local identity presented to the server (required)")
		remoteID = flag.String("server-id", "", "expected server identity (optional, verified if set)")
		user     = flag.String("user", "", "EAP-MSCHAPv2 username (enables EAP instead of client PSK)")
		pass     = flag.String("pass", "", "EAP-MSCHAPv2 password")
		tunName  = flag.String("tun", "", "TUN interface name (empty = kernel picks)")
		fullTun  = flag.Bool("full-tunnel", true, "route all traffic through the VPN (default route)")
		noRoute  = flag.Bool("no-route", false, "do not modify routing/addresses (diagnostic)")
	)
	flag.Parse()

	if *server == "" || *psk == "" || *idStr == "" {
		flag.Usage()
		log.Fatal("-server, -psk and -id are required")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	cfg := ike.ClientConfig{
		ServerHost:  *server,
		ServerPort:  *port,
		PSK:         []byte(*psk),
		LocalID:     parseIdentity(*idStr),
		EAPUsername: *user,
		EAPPassword: *pass,
		Logger:      logger,
	}
	if *remoteID != "" {
		id := parseIdentity(*remoteID)
		cfg.RemoteID = &id
	}

	// 1. Handshake.
	client := ike.NewClient(cfg)
	res, err := client.Connect()
	if err != nil {
		log.Fatalf("ikev2: connect failed: %v", err)
	}
	defer client.Close()
	logger.Printf("ikev2: connected. internal IP %s, netmask %s, DNS %v",
		res.AssignedIP, res.Netmask, res.DNS)

	// 2. Open TUN.
	tun, err := dataplane.OpenTUN(*tunName)
	if err != nil {
		log.Fatalf("ikev2: open TUN: %v", err)
	}
	defer tun.Close()
	logger.Printf("ikev2: opened TUN %s", tun.Name())

	// 3. Build the data-path tunnel and pump.
	tunnel, err := res.BuildTunnel()
	if err != nil {
		log.Fatalf("ikev2: build tunnel: %v", err)
	}

	// The pump sends outbound ESP to the server via a dedicated UDP socket on
	// port 4500 (NAT-T). Inbound ESP is read on that same socket.
	espConn, err := net.DialUDP("udp", nil, res.ServerAddr)
	if err != nil {
		log.Fatalf("ikev2: ESP socket: %v", err)
	}
	defer espConn.Close()

	send := func(esp []byte, _ *net.UDPAddr, udpEncap bool) {
		// Under NAT-T, ESP on 4500 needs no non-ESP marker (that marker is only
		// for IKE); ESP packets are sent as-is.
		if _, werr := espConn.Write(esp); werr != nil {
			logger.Printf("ikev2: ESP send error: %v", werr)
		}
	}

	pump := dataplane.NewPump(tun, send, logger)
	pump.AddTunnel(tunnel)       // inbound demux by our SPI
	pump.SetDefaultRoute(tunnel) // outbound: everything goes to the server
	go pump.Run()
	defer pump.Close()

	// 4. Inbound ESP read loop.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rerr := espConn.Read(buf)
			if rerr != nil {
				return
			}
			pkt := buf[:n]
			// Strip a non-ESP marker if present (shouldn't be on ESP, but be safe).
			if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
				continue // keepalive / non-ESP
			}
			pump.HandleESP(append([]byte(nil), pkt...))
		}
	}()

	// 5. NAT keepalives: a single 0xFF byte on 4500 every 20s holds the NAT
	// binding open (RFC 3948 2.3).
	stopKA := make(chan struct{})
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopKA:
				return
			case <-t.C:
				espConn.Write([]byte{0xff})
			}
		}
	}()
	defer close(stopKA)

	// 6. Routing.
	if !*noRoute {
		srvIP := res.ServerAddr.IP
		if r := net.ParseIP(*server); r != nil {
			srvIP = r
		} else if ips, lerr := net.LookupIP(*server); lerr == nil {
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					srvIP = v4
					break
				}
			}
		}
		router := dataplane.NewClientRouter(dataplane.ClientNetConfig{
			TUNName:    tun.Name(),
			AssignedIP: res.AssignedIP,
			Netmask:    res.Netmask,
			ServerIP:   srvIP,
			DNS:        res.DNS,
			FullTunnel: *fullTun,
		})
		if err := router.Apply(); err != nil {
			logger.Printf("ikev2: routing setup failed: %v (continuing without routes)", err)
		} else {
			logger.Printf("ikev2: routing configured (full-tunnel=%v)", *fullTun)
			defer func() {
				if rerr := router.Revert(); rerr != nil {
					logger.Printf("ikev2: route cleanup: %v", rerr)
				}
			}()
		}
	}

	logger.Printf("ikev2: tunnel up. Press Ctrl-C to disconnect.")

	// 7. Wait for signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Printf("ikev2: disconnecting")
}

func parseIdentity(s string) ike.Identity {
	if ip := net.ParseIP(s); ip != nil {
		return ike.IPIdentity(ip)
	}
	return ike.FQDNIdentity(s)
}
