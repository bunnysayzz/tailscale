// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"tailscale.com/util/eventbus/eventbustest"
)

func TestInjectionQueueCloseWakesAllReaders(t *testing.T) {
	for _, started := range []bool{false, true} {
		name := "before-start"
		if started {
			name = "after-start"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, w := newFakeTUN(t.Logf, eventbustest.NewBus(t), false)
				t.Cleanup(func() { w.Close() })
				if started {
					w.Start()
				}
				var readers sync.WaitGroup
				for range 8 {
					readers.Go(func() {
						slab, packets := getSinglePacketReadArgs()
						// Subsequent reads must also return EOF rather than
						// processing zero-value packets from a closed channel.
						for range 2 {
							if n, err := w.InjectionQueue().Read(slab, packets); n != 0 || err != io.EOF {
								t.Errorf("Read after Close = %d, %v; want 0, EOF", n, err)
							}
						}
					})
				}
				synctest.Wait() // All readers are blocked in Read or awaitStart.
				var closers sync.WaitGroup
				for range 4 {
					closers.Go(func() {
						if err := w.Close(); err != nil {
							t.Errorf("Close: %v", err)
						}
					})
				}
				closers.Wait()
				readers.Wait()
				select {
				case _, ok := <-w.injectionQueue.ch:
					if ok {
						t.Error("injection channel contains a packet after Close")
					}
				default:
					t.Error("injection channel is still open after Close")
				}
			})
		})
	}
}

// Model an active sender paused after its closed check but before its send.
// Close must signal shutdown immediately, but cannot close the injection
// channel until that sender releases outboundMu.
func TestInjectionQueueCloseWaitsForActiveSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, w := newFakeTUN(t.Logf, eventbustest.NewBus(t), false)
		t.Cleanup(func() { w.Close() })
		w.Start()
		w.outboundMu.Acquire()
		holdingSender := true
		defer func() {
			if holdingSender {
				w.outboundMu.Release()
			}
		}()
		closed := make(chan error, 1)
		go func() { closed <- w.Close() }()
		synctest.Wait()
		select {
		case <-w.closed:
		default:
			t.Error("Close did not signal shutdown before waiting for the sender")
		}
		select {
		case err := <-closed:
			t.Errorf("Close returned while the sender held outboundMu: %v", err)
		default:
		}
		select {
		case _, ok := <-w.injectionQueue.ch:
			t.Fatalf("injection channel became readable while sender held outboundMu (open=%v)", ok)
		default:
		}
		var released atomic.Int32
		// A sender that already passed its closed check can still accept a
		// packet. It must be drained exactly once after the sender finishes.
		w.injectionQueue.ch <- tunInjectedRead{packet: newInjectionTestPacket([]byte{1}, &released)}
		w.outboundMu.Release()
		holdingSender = false
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if got := released.Load(); got != 1 {
			t.Fatalf("accepted packet released %d times, want 1", got)
		}
		// Later senders must observe closed under the same semaphore rather
		// than trying to send on the now-closed channel.
		var senders sync.WaitGroup
		for range 8 {
			senders.Go(func() {
				if err := w.InjectOutboundPacketBuffer(newInjectionTestPacket([]byte{2}, &released)); err != ErrClosed {
					t.Errorf("late injection = %v, want ErrClosed", err)
				}
			})
		}
		senders.Wait()
		if got := released.Load(); got != 9 {
			t.Errorf("released %d accepted/rejected packets, want 9", got)
		}
	})
}
