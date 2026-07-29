package rosenpass

import (
	"context"
	"encoding/binary"
	"sync"
	"time"
)

const PSKSize = 32

type Session struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	psk    []byte
	ch     chan []byte
}

func NewSession(interval time.Duration) *Session {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		ctx:    ctx,
		cancel: cancel,
		psk:    make([]byte, PSKSize),
		ch:     make(chan []byte, 1),
	}
	go s.run(interval)
	return s
}

func (s *Session) run(interval time.Duration) {
	s.wg.Add(1)
	defer s.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			key := make([]byte, PSKSize)
			binary.BigEndian.PutUint64(key[:8], uint64(time.Now().UnixNano()))
			copy(s.psk, key)
			select {
			case s.ch <- key:
			default:
			}
		}
	}
}

func (s *Session) PSK() []byte {
	return s.psk
}

func (s *Session) Subscribe() <-chan []byte {
	return s.ch
}

func (s *Session) Close() {
	s.cancel()
	s.wg.Wait()
}
