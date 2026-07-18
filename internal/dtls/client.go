package dtls

import (
	"errors"
	"fmt"
)

// clientHandshake runs the PSK handshake in the client role:
//
//	-> ClientHello
//	<- HelloVerifyRequest (cookie)
//	-> ClientHello (with cookie)
//	<- ServerHello, [ServerKeyExchange], ServerHelloDone
//	-> ClientKeyExchange, ChangeCipherSpec, Finished
//	<- ChangeCipherSpec, Finished
func (c *Conn) clientHandshake() error {
	hs := newHandshakeState()

	random, err := newRandom()
	if err != nil {
		return err
	}
	hs.clientRand = random

	hello := clientHello{
		version:      version1_2,
		random:       random,
		sessionID:    c.cfg.SessionID,
		cipherSuites: suiteIDs(),
	}

	// Flight 1: ClientHello with no cookie. The server is expected to answer with
	// a HelloVerifyRequest, but a server configured not to may go straight to
	// ServerHello, so both are accepted.
	msg := handshakeMsg{typ: handshakeClientHello, seq: hs.sendSeq, body: hello.marshal()}
	flight, err := c.sendFlight(hs, []handshakeMsg{msg})
	if err != nil {
		return err
	}
	hs.sendSeq++

	got, err := c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
		_, hvr := findMsg(msgs, handshakeHelloVerifyReq)
		_, done := findMsg(msgs, handshakeServerHelloDone)
		return hvr || done
	})
	if err != nil {
		return err
	}

	// Flight 2: repeat the ClientHello carrying the cookie. Per RFC 6347 the
	// HelloVerifyRequest and the two ClientHellos are excluded from the
	// transcript, so the hash is started fresh from the second ClientHello.
	if hvr, ok := findMsg(got, handshakeHelloVerifyReq); ok {
		verify, err := parseHelloVerifyRequest(hvr.body)
		if err != nil {
			return err
		}
		hello.cookie = verify.cookie
		msg = handshakeMsg{typ: handshakeClientHello, seq: hs.sendSeq, body: hello.marshal()}
		flight, err = c.sendFlight(hs, []handshakeMsg{msg})
		if err != nil {
			return err
		}
		hs.sendSeq++

		got, err = c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
			_, done := findMsg(msgs, handshakeServerHelloDone)
			return done
		})
		if err != nil {
			return err
		}
	}
	hs.record(msg)

	sh, ok := findMsg(got, handshakeServerHello)
	if !ok {
		return errors.New("dtls: server never sent a ServerHello")
	}
	hello2, err := parseServerHello(sh.body)
	if err != nil {
		return err
	}
	s, err := suiteByID(hello2.cipherSuite)
	if err != nil {
		return err
	}
	c.suite = s
	hs.serverRand = hello2.random

	// Record the server's flight in the order it was sent.
	for _, typ := range []uint8{handshakeServerHello, handshakeServerKeyExchange, handshakeServerHelloDone} {
		if m, ok := findMsg(got, typ); ok {
			hs.record(m)
		}
	}

	// Flight 3: ClientKeyExchange, ChangeCipherSpec, Finished.
	cke := handshakeMsg{
		typ:  handshakeClientKeyExchange,
		seq:  hs.sendSeq,
		body: pskClientKeyExchange{identity: c.cfg.PSKIdentity}.marshal(),
	}
	hs.sendSeq++
	hs.record(cke)

	master := masterSecret(s.prfHash, pskPremaster(c.cfg.PSK), hs.clientRand, hs.serverRand)
	c.master = master
	km := expandKeys(s, master, hs.clientRand, hs.serverRand)

	writeAEAD, err := newAEAD(km.clientKey, km.clientIV)
	if err != nil {
		return err
	}
	readAEAD, err := newAEAD(km.serverKey, km.serverIV)
	if err != nil {
		return err
	}

	// The client's Finished covers everything through its own ClientKeyExchange.
	verifyData := finishedVerifyData(s, master, labelClientFinished, hs.transcript)
	fin := handshakeMsg{typ: handshakeFinished, seq: hs.sendSeq, body: verifyData}
	hs.sendSeq++
	hs.record(fin)

	if _, err := c.sendFlight(hs, []handshakeMsg{cke}); err != nil {
		return err
	}
	if err := c.changeCipherSpec(writeAEAD); err != nil {
		return err
	}
	if err := c.sendEncryptedHandshake(fin); err != nil {
		return err
	}

	// Flight 4: the server's ChangeCipherSpec and Finished. Its Finished covers
	// the transcript including ours.
	c.installReadKeys(readAEAD)
	got, err = c.readFlight(hs, nil, func(msgs []handshakeMsg) bool {
		_, ok := findMsg(msgs, handshakeFinished)
		return ok
	})
	if err != nil {
		return err
	}
	serverFin, ok := findMsg(got, handshakeFinished)
	if !ok {
		return errors.New("dtls: server never sent Finished")
	}
	if err := verifyFinished(s, master, labelServerFinished, hs.transcript, serverFin.body); err != nil {
		return err
	}
	return nil
}

// sendEncryptedHandshake emits a handshake message under the new write keys,
// which is how Finished is protected.
func (c *Conn) sendEncryptedHandshake(m handshakeMsg) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.out == nil {
		return fmt.Errorf("dtls: no write keys installed")
	}
	rec := c.buildRecordLocked(recordHandshake, m.marshal())
	_, err := c.conn.Write(rec)
	return err
}

// suiteIDs is the offered cipher suite list, in preference order.
func suiteIDs() []uint16 {
	out := make([]uint16, 0, len(supportedSuites))
	for _, s := range supportedSuites {
		out = append(out, s.id)
	}
	return out
}
