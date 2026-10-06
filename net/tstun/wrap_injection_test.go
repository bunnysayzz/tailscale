// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

func newInjectionTestPacket(data []byte, released *atomic.Int32) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data), OnRelease: func() { released.Add(1) },
	})
}

func TestInjectOutboundPacketBufferOwnership(t *testing.T) {
	for _, state := range []string{"read", "buffered-close", "closed", "canceled", "empty", "oversize", "captured"} {
		t.Run(state, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			_, w := newFakeTUN(t.Logf, bus, false)
			t.Cleanup(func() { w.Close() })
			ctx := context.Background()
			data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
			wantErr := error(nil)
			switch state {
			case "closed":
				w.Close()
				wantErr = ErrClosed
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantErr = context.Canceled
			case "empty":
				data = nil
			case "oversize":
				data = make([]byte, MaxPacketSize+1)
				wantErr = errPacketTooBig
			}
			if state == "captured" {
				w.InstallCaptureHook(func(path packet.CapturePath, _ time.Time, got []byte, _ packet.CaptureMeta) {
					if path != packet.SynthesizedToPeer || !bytes.Equal(got, data) {
						t.Errorf("capture = %v, %x", path, got)
					}
				})
			}
			var released atomic.Int32
			pkt := newInjectionTestPacket(data, &released)
			err := w.InjectOutboundPacketBufferContext(ctx, pkt)
			if !errors.Is(err, wantErr) {
				t.Fatalf("InjectOutboundPacketBufferContext = %v, want %v", err, wantErr)
			}
			if state == "read" || state == "buffered-close" || state == "captured" {
				if got := released.Load(); got != 0 {
					t.Fatalf("released %d packets before consuming injection, want 0", got)
				}
				if state == "buffered-close" {
					w.Close()
				} else {
					w.Start()
					slab, packets := getSinglePacketReadArgs()
					n, err := w.InjectionQueue().Read(slab, packets)
					if n != 1 || err != nil {
						t.Fatalf("Read = %d, %v", n, err)
					}
					if got := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]; !bytes.Equal(got, data) {
						t.Errorf("Read = %x, want %x", got, data)
					}
				}
			}
			if got := released.Load(); got != 1 {
				t.Errorf("released %d packets, want 1", got)
			}
		})
	}
}

// Run the reentrant callbacks in a subprocess so a regression cannot leave
// cleanup or another Close caller stuck on the same sync.Once.
func TestCloseWithReentrantRelease(t *testing.T) {
	const helperEnv = "TS_TSTUN_REENTRANT_RELEASE_HELPER"
	if os.Getenv(helperEnv) != "" {
		bus := eventbustest.NewBus(t)
		ftun, w := newFakeTUN(t.Logf, bus, false)
		t.Cleanup(func() { w.Close() })
		var released atomic.Int32
		onRelease := func() {
			released.Add(1)
			select {
			case <-ftun.closechan:
			default:
				t.Error("underlying TUN is still open during release callback")
			}
			if err := w.Close(); err != nil {
				t.Errorf("reentrant Close: %v", err)
			}
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData([]byte{1}), OnRelease: onRelease,
		})
		if err := w.InjectOutboundPacketBuffer(pkt); err != nil {
			t.Fatal(err)
		}
		// Concurrent drainers must release the result exactly once, even
		// when its callback starts another Close call.
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 8 {
			wg.Go(func() {
				<-start
				if err := w.Close(); err != nil {
					t.Errorf("concurrent Close: %v", err)
				}
			})
		}
		close(start)
		wg.Wait()
		if err := w.Close(); err != nil {
			t.Fatalf("repeated Close: %v", err)
		}
		if got := released.Load(); got != 1 {
			t.Errorf("release callback called %d times, want 1", got)
		}
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCloseWithReentrantRelease$", "-test.v")
	cmd.Env = append(os.Environ(), helperEnv+"=1",
		"GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("reentrant release blocked Close: %v\n%s", ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("reentrant release: %v\n%s", err, out)
	}
}

// A background sender waiting for the reader must not prevent a second sender
// from canceling. synctest.Wait establishes that both senders are blocked before
// cancellation, without sleeps or relying on scheduling.
func TestInjectOutboundCancellationBehindBlockedSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := eventbustest.NewBus(t)
		_, w := newFakeTUN(t.Logf, bus, false)
		t.Cleanup(func() { w.Close() })
		var released atomic.Int32
		data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
		if err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)); err != nil {
			t.Fatal(err)
		}
		blocked := make(chan error, 1)
		go func() { blocked <- w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)) }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		canceled := make(chan error, 1)
		go func() { canceled <- w.InjectOutboundPacketBufferContext(ctx, newInjectionTestPacket(data, &released)) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-canceled:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("injection = %v, want context.Canceled", err)
			}
		default:
			t.Fatal("canceled sender is stuck behind a background sender")
		}
		if got := released.Load(); got != 1 {
			t.Fatalf("released %d packets after cancellation, want 1", got)
		}
		select {
		case err := <-blocked:
			t.Fatalf("background sender returned before Wrapper.Close: %v", err)
		default:
		}
		w.Close()
		if err := <-blocked; !errors.Is(err, ErrClosed) {
			t.Fatalf("background injection = %v, want ErrClosed", err)
		}
		if got := released.Load(); got != 3 {
			t.Errorf("released %d packets after Close, want 3", got)
		}
	})
}

func TestInjectOutboundPacketBufferCancellationWithFullQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := eventbustest.NewBus(t)
		_, w := newFakeTUN(t.Logf, bus, false)
		t.Cleanup(func() { w.Close() })
		data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
		var released atomic.Int32
		if err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- w.InjectOutboundPacketBufferContext(ctx, newInjectionTestPacket(data, &released))
		}()
		// Serialization was acquired immediately, but the enqueue fast path
		// must fall back to a cancellable wait on the full delivery queue.
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("injection = %v, want context.Canceled", err)
		}
		if got := released.Load(); got != 1 {
			t.Fatalf("released %d packets after cancellation, want 1", got)
		}
		w.Start()
		slab, packets := getSinglePacketReadArgs()
		if n, err := w.InjectionQueue().Read(slab, packets); n != 1 || err != nil {
			t.Fatalf("Read accepted packet = %d, %v", n, err)
		}
		if got := released.Load(); got != 2 {
			t.Errorf("released %d packets after Read, want 2", got)
		}
	})
}

func TestInjectOutboundContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := eventbustest.NewBus(t)
		_, w := newFakeTUN(t.Logf, bus, false)
		t.Cleanup(func() { w.Close() })
		first := udp4("1.2.3.4", "5.6.7.8", 98, 98)
		if err := w.InjectOutbound(first); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- w.InjectOutboundContext(ctx, []byte{2}) }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("InjectOutboundContext = %v, want context.Canceled", err)
		}
		// Cancellation affects only the waiting injection, not an accepted packet.
		w.Start()
		slab, packets := getSinglePacketReadArgs()
		n, err := w.InjectionQueue().Read(slab, packets)
		if n != 1 || err != nil {
			t.Fatalf("Read = %d, %v", n, err)
		}
		if got := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]; !bytes.Equal(got, first) {
			t.Errorf("Read = %x, want %x", got, first)
		}
		if err := w.InjectOutbound([]byte{3}); err != nil {
			t.Fatal(err)
		}
		w.Close()
		if err := w.InjectOutbound([]byte{4}); !errors.Is(err, ErrClosed) {
			t.Errorf("InjectOutbound on closed Wrapper = %v, want ErrClosed", err)
		}
	})
}

func TestInjectOutboundConcurrentReadAndClose(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(fmt.Sprintf("queues=%d", queues), func(t *testing.T) {
			testInjectOutboundConcurrentReadAndClose(t, queues)
		})
	}
}

func testInjectOutboundConcurrentReadAndClose(t *testing.T, queues int) {
	bus := eventbustest.NewBus(t)
	w := Wrap(t.Logf, newFakeMQ(queues), new(usermetric.Registry), bus)
	w.disableFilter = true
	w.Start()
	t.Cleanup(func() { w.Close() })
	const writers, count = 8, 64
	var released atomic.Int32
	data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
	// Ensure at least one accepted packet is processed by a reader before
	// starting Close, instead of allowing every producer to lose to Close.
	firstReleased := make(chan struct{})
	first := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
		OnRelease: func() {
			released.Add(1)
			close(firstReleased)
		},
	})
	if err := w.InjectOutboundPacketBuffer(first); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		wg.Go(func() {
			<-start
			for range count {
				err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released))
				if err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("injection: %v", err)
				}
			}
		})
	}
	readQueues := w.Queues()
	// Stress multiple injection readers racing each other and Close's drain,
	// while every native queue also has a reader waiting for shutdown.
	for range 3 {
		readQueues = append(readQueues, w.InjectionQueue())
	}
	for _, q := range readQueues {
		wg.Go(func() {
			<-start
			slab, packets := getSinglePacketReadArgs()
			for {
				if _, err := q.Read(slab, packets); err != nil {
					return
				}
			}
		})
	}
	wg.Go(func() { <-start; <-firstReleased; w.Close() })
	close(start)
	wg.Wait()
	if got := released.Load(); got != writers*count+1 {
		t.Errorf("released %d packets, want %d", got, writers*count+1)
	}
}

// BenchmarkInjectOutboundPipeline measures a dedicated injector feeding an
// independent reader with a live cancellable context. It excludes WireGuard
// encryption and OS/network I/O. Exactly b.N packets are sent, so cleanup does
// not leave an extra injection waiting for a reader that has stopped.
func BenchmarkInjectOutboundPipeline(b *testing.B) {
	for _, size := range []int{64, 1280} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			bus := eventbustest.NewBus(b)
			_, w := newFakeTUN(b.Logf, bus, false)
			defer w.Close()
			w.Start()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &packet.UDP4Header{
				IP4Header: packet.IP4Header{
					Src: netip.MustParseAddr("100.64.1.2"), Dst: netip.MustParseAddr("100.64.1.3"),
				},
				SrcPort: 1234, DstPort: 5678,
			}
			data := packet.Generate(h, bytes.Repeat([]byte{0x55}, size-28))
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			defer pkt.DecRef()
			slab, packets := getSinglePacketReadArgs()
			sent := make(chan error, 1)
			done := make(chan struct{})
			defer func() { cancel(); w.Close(); <-done }()
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			go func() {
				defer close(done)
				for range b.N {
					if err := w.InjectOutboundPacketBufferContext(ctx, pkt.IncRef()); err != nil {
						sent <- err
						return
					}
				}
				sent <- nil
			}()
			for range b.N {
				if n, err := w.InjectionQueue().Read(slab, packets); n != 1 || err != nil {
					b.Fatalf("Read = %d, %v", n, err)
				}
			}
			b.StopTimer()
			if err := <-sent; err != nil {
				b.Fatal(err)
			}
		})
	}
}

func BenchmarkInjectOutboundPacketBuffer(b *testing.B) {
	bus := eventbustest.NewBus(b)
	_, w := newFakeTUN(b.Logf, bus, false)
	defer w.Close()
	w.Start()
	data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	defer pkt.DecRef()
	slab, packets := getSinglePacketReadArgs()
	b.ReportAllocs()
	for b.Loop() {
		if err := w.InjectOutboundPacketBuffer(pkt.IncRef()); err != nil {
			b.Fatal(err)
		}
		if _, err := w.InjectionQueue().Read(slab, packets); err != nil {
			b.Fatal(err)
		}
	}
}
