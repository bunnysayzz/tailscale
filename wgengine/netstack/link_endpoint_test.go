// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestQueue(t testing.TB, size int) *queue {
	t.Helper()
	q := &queue{c: make(chan *stack.PacketBuffer, size), closedCh: make(chan struct{})}
	t.Cleanup(func() { q.Close(); q.Drain() })
	return q
}

func newQueueTestPacket(released *atomic.Int32) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{OnRelease: func() { released.Add(1) }})
}

func TestQueueReadAndDrain(t *testing.T) {
	q := newTestQueue(t, 2)
	var released atomic.Int32
	first := newQueueTestPacket(&released)
	second := newQueueTestPacket(&released)
	for _, pkt := range []*stack.PacketBuffer{first, second} {
		err := q.Write(pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("released %d queued packets, want 0", got)
	}
	if got := q.Num(); got != 2 {
		t.Fatalf("Num = %d, want 2", got)
	}
	pkt := q.Read()
	if pkt != first {
		t.Fatalf("Read = %p, want %p", pkt, first)
	}
	pkt.DecRef()
	if got := released.Load(); got != 1 {
		t.Fatalf("released %d packets after Read, want 1", got)
	}
	q.Close()
	if got := q.Drain(); got != 1 {
		t.Fatalf("Drain = %d, want 1", got)
	}
	if got := released.Load(); got != 2 {
		t.Fatalf("released %d packets after Drain, want 2", got)
	}
	if pkt := q.Read(); pkt != nil {
		pkt.DecRef()
		t.Fatal("Read returned a packet after Drain")
	}
}

func TestQueueWriteFull(t *testing.T) {
	q := newTestQueue(t, 1)
	var released atomic.Int32
	queued := newQueueTestPacket(&released)
	err := q.Write(queued)
	queued.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	rejected := newQueueTestPacket(&released)
	done := make(chan tcpip.Error, 1)
	go func() { done <- q.Write(rejected) }()
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		q.Close()
		<-done
		rejected.DecRef()
		t.Fatal("Write blocked on a full queue")
	}
	if got := released.Load(); got != 0 {
		t.Errorf("released %d packets before caller DecRef, want 0", got)
	}
	rejected.DecRef()
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Errorf("Write = %v, want ErrNoBufferSpace", err)
	}
	if got := released.Load(); got != 1 {
		t.Errorf("released %d packets after rejection, want 1", got)
	}
	if got := q.Num(); got != 1 {
		t.Errorf("Num = %d, want 1", got)
	}
	// The rejection must not prevent later writes from progressing.
	pkt := q.Read()
	pkt.DecRef()
	next := newQueueTestPacket(&released)
	err = q.Write(next)
	next.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	q.Close()
	if got := q.Drain(); got != 1 {
		t.Errorf("Drain = %d, want 1", got)
	}
	if got := released.Load(); got != 3 {
		t.Errorf("released %d packets, want 3", got)
	}
}

func TestQueueWriteClosed(t *testing.T) {
	for _, state := range []string{"closed", "close-signaled"} {
		t.Run(state, func(t *testing.T) {
			q := newTestQueue(t, 0)
			if state == "closed" {
				q.Close()
			} else {
				q.closeOnce.Do(func() { close(q.closedCh) })
			}
			var released atomic.Int32
			pkt := newQueueTestPacket(&released)
			err := q.Write(pkt)
			if got := released.Load(); got != 0 {
				t.Errorf("released %d packets before caller DecRef, want 0", got)
			}
			pkt.DecRef()
			if _, ok := err.(*tcpip.ErrClosedForSend); !ok {
				t.Errorf("Write = %v, want ErrClosedForSend", err)
			}
			if got := released.Load(); got != 1 {
				t.Errorf("released %d packets, want 1", got)
			}
		})
	}
}

func TestQueueConcurrentWriteReadAndClose(t *testing.T) {
	q := newTestQueue(t, 8)
	const writers, packets = 8, 64
	var released atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		wg.Go(func() {
			<-start
			for range packets {
				pkt := newQueueTestPacket(&released)
				err := q.Write(pkt)
				pkt.DecRef()
				switch err.(type) {
				case nil, *tcpip.ErrNoBufferSpace, *tcpip.ErrClosedForSend:
				default:
					t.Errorf("Write: unexpected error %v", err)
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		for {
			pkt := q.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			pkt.DecRef()
		}
	})
	wg.Go(func() { <-start; q.Close() })
	close(start)
	wg.Wait()
	q.Drain()
	if got := released.Load(); got != writers*packets {
		t.Errorf("released %d packets, want %d", got, writers*packets)
	}
}

// BenchmarkQueueWriteRead measures admission and reference handling without
// saturation. It can also run against the blocking implementation for comparison.
func BenchmarkQueueWriteRead(b *testing.B) {
	q := newTestQueue(b, 512)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()
	b.ReportAllocs()
	for b.Loop() {
		if err := q.Write(pkt); err != nil {
			b.Fatal(err)
		}
		q.Read().DecRef()
	}
}
