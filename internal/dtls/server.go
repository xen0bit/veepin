package dtls

import (
	"errors"
	"fmt"
)

// serverHandshake runs the PSK handshake in the server role. It always issues a
// HelloVerifyRequest for the first ClientHello, so no state is allocated for a
// peer that has not proven it can receive at its claimed source address — DTLS's
// defence against being used as an amplification reflector.
func (c *Conn) serverHandshake() error {
	hs := newHandshakeState()

	cookieSecret, err := randomBytes(32)
	if err != nil {
		return err
	}
	peer := []byte(c.conn.RemoteAddr().String())
	cookie := cookieMAC(cookieSecret, peer)

	// Flight 1: wait for a ClientHello.
	got, err := c.readFlight(hs, nil, func(msgs []handshakeMsg) bool {
		_, ok := findMsg(msgs, handshakeClientHello)
		return ok
	})
	if err != nil {
		return err
	}
	chMsg, _ := findMsg(got, handshakeClientHello)
	ch, err := parseClientHello(chMsg.body)
	if err != nil {
		return err
	}

	// Flight 2: if the client has not echoed a valid cookie, send one and wait
	// for it to come back.
	if !constantTimeEqual(ch.cookie, cookie) {
		hvr := handshakeMsg{
			typ:  handshakeHelloVerifyReq,
			seq:  hs.sendSeq,
			body: helloVerifyRequest{version: version1_2, cookie: cookie}.marshal(),
		}
		flight, err := c.sendFlight(hs, []handshakeMsg{hvr})
		if err != nil {
			return err
		}
		hs.sendSeq++

		// The client restarts its message sequence for the second ClientHello, so
		// the reassembler is reset to expect it.
		hs.reasm = newReassembler()
		hs.reasm.next = chMsg.seq + 1

		got, err = c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
			_, ok := findMsg(msgs, handshakeClientHello)
			return ok
		})
		if err != nil {
			return err
		}
		chMsg, _ = findMsg(got, handshakeClientHello)
		ch, err = parseClientHello(chMsg.body)
		if err != nil {
			return err
		}
		if !constantTimeEqual(ch.cookie, cookie) {
			return errors.New("dtls: client returned an invalid cookie")
		}
	}
	// Per RFC 6347 the transcript starts at the cookie-bearing ClientHello.
	hs.record(chMsg)
	hs.clientRand = ch.random

	s, err := selectSuite(ch.cipherSuites)
	if err != nil {
		return err
	}
	c.suite = s

	serverRand, err := newRandom()
	if err != nil {
		return err
	}
	hs.serverRand = serverRand

	// Flight 3: ServerHello, ServerKeyExchange (an empty PSK hint), ServerHelloDone.
	sh := handshakeMsg{
		typ: handshakeServerHello,
		seq: hs.sendSeq,
		body: serverHello{
			version:     version1_2,
			random:      serverRand,
			sessionID:   ch.sessionID, // echo it: AnyConnect's App-ID rides here
			cipherSuite: s.id,
		}.marshal(),
	}
	hs.sendSeq++
	ske := handshakeMsg{typ: handshakeServerKeyExchange, seq: hs.sendSeq, body: pskIdentityHint{}.marshal()}
	hs.sendSeq++
	shd := handshakeMsg{typ: handshakeServerHelloDone, seq: hs.sendSeq}
	hs.sendSeq++

	for _, m := range []handshakeMsg{sh, ske, shd} {
		hs.record(m)
	}
	flight, err := c.sendFlight(hs, []handshakeMsg{sh, ske, shd})
	if err != nil {
		return err
	}

	// Flight 4: ClientKeyExchange, ChangeCipherSpec, Finished. The keys must be
	// derived before the client's Finished can be decrypted, so they are computed
	// as soon as the ClientKeyExchange lands.
	got, err = c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
		_, ok := findMsg(msgs, handshakeClientKeyExchange)
		return ok
	})
	if err != nil {
		return err
	}
	cke, ok := findMsg(got, handshakeClientKeyExchange)
	if !ok {
		return errors.New("dtls: client never sent a ClientKeyExchange")
	}
	if _, err := parsePSKClientKeyExchange(cke.body); err != nil {
		return err
	}
	hs.record(cke)

	master := masterSecret(s.prfHash, pskPremaster(c.cfg.PSK), hs.clientRand, hs.serverRand)
	c.master = master
	km := expandKeys(s, master, hs.clientRand, hs.serverRand)

	readAEAD, err := newAEAD(km.clientKey, km.clientIV)
	if err != nil {
		return err
	}
	writeAEAD, err := newAEAD(km.serverKey, km.serverIV)
	if err != nil {
		return err
	}
	// The client's Finished arrives encrypted under the epoch it just entered.
	c.installReadKeys(readAEAD)

	// What the client's Finished covers: everything through its ClientKeyExchange.
	clientTranscript := append([]byte(nil), hs.transcript...)

	got, err = c.readFlight(hs, flight, func(msgs []handshakeMsg) bool {
		_, ok := findMsg(msgs, handshakeFinished)
		return ok
	})
	if err != nil {
		return err
	}
	clientFin, ok := findMsg(got, handshakeFinished)
	if !ok {
		return errors.New("dtls: client never sent Finished")
	}
	if err := verifyFinished(s, master, labelClientFinished, clientTranscript, clientFin.body); err != nil {
		return err
	}
	hs.record(clientFin)

	// Flight 5: our ChangeCipherSpec and Finished, over the transcript including
	// the client's Finished.
	if err := c.changeCipherSpec(writeAEAD); err != nil {
		return err
	}
	verifyData := finishedVerifyData(s, master, labelServerFinished, hs.transcript)
	fin := handshakeMsg{typ: handshakeFinished, seq: hs.sendSeq, body: verifyData}
	hs.sendSeq++
	return c.sendEncryptedHandshake(fin)
}

// selectSuite picks the first offered suite we support, in our preference order
// rather than the client's.
func selectSuite(offered []uint16) (suite, error) {
	for _, s := range supportedSuites {
		for _, id := range offered {
			if id == s.id {
				return s, nil
			}
		}
	}
	return suite{}, fmt.Errorf("dtls: no mutually supported cipher suite among %d offered", len(offered))
}
