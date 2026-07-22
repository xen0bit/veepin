package dataplane

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestBatchConnRoundTrip proves WriteBatch actually puts the given datagrams on
// the wire (so the benchmarks below are measuring real sends, not a no-op) and
// that ReadBatch recovers them.
func TestBatchConnRoundTrip(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer recv.Close()
	send, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer send.Close()

	want := [][]byte{[]byte("alpha"), []byte("bravo!!"), []byte("charlie-3"), []byte("d")}
	bc := NewBatchConn(send)
	n, err := bc.WriteBatch(want, nil)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if n != len(want) {
		t.Fatalf("WriteBatch sent %d of %d", n, len(want))
	}

	// Recover them with a batched read and check the set (UDP need not preserve
	// order, though loopback usually does).
	bufs := make([][]byte, len(want))
	for i := range bufs {
		bufs[i] = make([]byte, 64)
	}
	sizes := make([]int, len(want))
	rc := NewBatchConn(recv)
	_ = recv.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := map[string]bool{}
	for len(got) < len(want) {
		rn, err := rc.ReadBatch(bufs, sizes)
		if err != nil {
			t.Fatalf("ReadBatch (have %d/%d): %v", len(got), len(want), err)
		}
		for i := range rn {
			got[string(bufs[i][:sizes[i]])] = true
		}
	}
	for _, w := range want {
		if !got[string(w)] {
			t.Errorf("datagram %q not received", w)
		}
	}
}

// benchUDPPair sets up a connected sender socket and its receiver with large
// buffers. The caller owns the receive side: send benchmarks start drain to
// throw the datagrams away, the receive benchmarks read them as the measured
// work. stop tears both down.
func benchUDPPair(b *testing.B) (send, recv *net.UDPConn, stop func()) {
	b.Helper()
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	_ = recv.SetReadBuffer(8 << 20)
	send, err = net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		recv.Close()
		b.Fatalf("dial: %v", err)
	}
	_ = send.SetWriteBuffer(8 << 20)
	return send, recv, func() { send.Close(); recv.Close() }
}

// drain discards everything recv delivers so a send benchmark's receive buffer
// never fills and drops. Returns when recv is closed.
func drain(recv *net.UDPConn) {
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, err := recv.Read(buf); err != nil {
				return // closed
			}
		}
	}()
}

const benchPayload = 1400

// BenchmarkUDPSendSingle is the baseline: one datagram per Write syscall, which
// is what dataplane's Sender does today. MB/s is directly comparable with the
// batched benchmark below.
func BenchmarkUDPSendSingle(b *testing.B) {
	send, recv, stop := benchUDPPair(b)
	defer stop()
	drain(recv)
	pkt := make([]byte, benchPayload)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := send.Write(pkt); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

// BenchmarkUDPSendBatch sends the same 1400-byte datagrams via sendmmsg in
// batches of K, so each loop iteration is roughly one syscall for K datagrams.
// b.SetBytes(K*payload) keeps MB/s comparable with the single benchmark.
func BenchmarkUDPSendBatch(b *testing.B) {
	for _, k := range []int{8, 16, 64, 256} {
		b.Run(fmt.Sprintf("batch-%d", k), func(b *testing.B) {
			send, recv, stop := benchUDPPair(b)
			defer stop()
			drain(recv)
			bc := NewBatchConn(send)
			pkts := make([][]byte, k)
			for i := range pkts {
				pkts[i] = make([]byte, benchPayload)
			}
			b.SetBytes(int64(k) * benchPayload)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := bc.WriteBatch(pkts, nil); err != nil {
					b.Fatalf("WriteBatch: %v", err)
				}
			}
		})
	}
}

// recvBurst is how many queued datagrams each receive-benchmark refill leaves in
// the socket buffer. It must be a multiple of every batch size tested below.
const recvBurst = 256

// refillRecv queues recvBurst datagrams on recv with the benchmark timer
// stopped, so the timed region of a receive benchmark is only the receive
// syscalls: the sender has already paid loopback's per-datagram delivery cost
// off the clock. That mirrors real ingress, where the NIC and softirq path fill
// the socket buffer and the process pays only the dequeue.
func refillRecv(b *testing.B, sender *BatchConn, recv *net.UDPConn, pkts [][]byte) {
	b.Helper()
	b.StopTimer()
	for sent := 0; sent < len(pkts); {
		n, err := sender.WriteBatch(pkts[sent:], nil)
		if err != nil {
			b.Fatalf("refill: %v", err)
		}
		sent += n
	}
	// A dropped refill datagram would otherwise block the reader forever.
	_ = recv.SetReadDeadline(time.Now().Add(5 * time.Second))
	b.StartTimer()
}

// BenchmarkUDPRecvSingle is the receive baseline: one datagram per Read
// syscall, against a socket buffer kept non-empty by untimed refills.
func BenchmarkUDPRecvSingle(b *testing.B) {
	send, recv, stop := benchUDPPair(b)
	defer stop()
	sender := NewBatchConn(send)
	pkts := make([][]byte, recvBurst)
	for i := range pkts {
		pkts[i] = make([]byte, benchPayload)
	}
	buf := make([]byte, 2048)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if i%recvBurst == 0 {
			refillRecv(b, sender, recv, pkts)
		}
		i++
		if _, err := recv.Read(buf); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// BenchmarkUDPRecvBatch drains the same queued datagrams K at a time via
// recvmmsg. Each timed iteration is one syscall for K datagrams;
// b.SetBytes(K*payload) keeps MB/s comparable with the single benchmark.
func BenchmarkUDPRecvBatch(b *testing.B) {
	for _, k := range []int{8, 16, 64, 256} {
		b.Run(fmt.Sprintf("batch-%d", k), func(b *testing.B) {
			send, recv, stop := benchUDPPair(b)
			defer stop()
			sender := NewBatchConn(send)
			pkts := make([][]byte, recvBurst)
			for i := range pkts {
				pkts[i] = make([]byte, benchPayload)
			}
			rc := NewBatchConn(recv)
			bufs := make([][]byte, k)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			sizes := make([]int, k)
			b.SetBytes(int64(k) * benchPayload)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if i%(recvBurst/k) == 0 {
					refillRecv(b, sender, recv, pkts)
				}
				i++
				n, err := rc.ReadBatch(bufs, sizes)
				if err != nil {
					b.Fatalf("ReadBatch: %v", err)
				}
				if n != k {
					// The buffer held a full burst, so a short read would mean
					// the iteration count and SetBytes no longer line up.
					b.Fatalf("ReadBatch returned %d of %d", n, k)
				}
			}
		})
	}
}
