// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/net/tstun"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
)

var queueTestLocalIP = netip.MustParseAddr("100.64.1.2")

// newQueueTestStack uses the production destination classifier, but small
// queues and no consumers so tests can deterministically force saturation.
func newQueueTestStack(t testing.TB, size int) (*stack.Stack, *linkEndpoint) {
	t.Helper()
	ns := &Impl{}
	ns.atomicIsLocalIPFunc.Store(func(a netip.Addr) bool { return a == queueTestLocalIP })
	ns.atomicIsVIPServiceIPFunc.Store(func(netip.Addr) bool { return false })
	ep := newLinkEndpoint(size, 1280, "", groNotSupported, ns.outboundQueueForPacket)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() { ep.Close(); s.Close(); s.Wait() })
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []netip.Addr{queueTestLocalIP, serviceIP} {
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          header.IPv4ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: nicID}})
	return s, ep
}

// An ACK without an endpoint bypasses the TCP forwarder and generates a
// synchronous reset in gVisor. DeliverLoopback marks the checksum validated.
func queueTestACK(src, dst netip.Addr) *stack.PacketBuffer {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 40})
	header.TCP(pkt.TransportHeader().Push(20)).Encode(&header.TCPFields{
		SrcPort: 12345, DstPort: 54321, DataOffset: 20, Flags: header.TCPFlagAck, AckNum: 1,
	})
	ih := header.IPv4(pkt.NetworkHeader().Push(20))
	ih.Encode(&header.IPv4Fields{
		TotalLength: 40, TTL: 64, Protocol: uint8(header.TCPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4()),
	})
	ih.SetChecksum(^ih.CalculateChecksum())
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	return pkt
}

func requireQueueTestReset(t *testing.T, ep *linkEndpoint, dest outboundQueue) {
	t.Helper()
	pkt := ep.Read(dest)
	if pkt == nil {
		t.Fatal("gVisor did not enqueue a reset")
	}
	defer pkt.DecRef()
	if !header.TCP(pkt.TransportHeader().Slice()).Flags().Contains(header.TCPFlagRst) {
		t.Fatal("reply is not a TCP reset")
	}
}

func TestLoopbackReplyWithFullQueue(t *testing.T) {
	_, ep := newQueueTestStack(t, 1)
	// Model the consumer dequeuing a packet, then another producer refilling
	// the queue before DeliverLoopback synchronously produces its reply.
	ack := queueTestACK(queueTestLocalIP, queueTestLocalIP)
	var pkts stack.PacketBufferList
	pkts.PushBack(ack)
	n, err := ep.WritePackets(pkts)
	ack.DecRef()
	if n != 1 || err != nil {
		t.Fatalf("WritePackets = %d, %v", n, err)
	}
	delivering := ep.Read(outboundLoopback)
	var released atomic.Int32
	filler := newQueueTestPacket(&released)
	err = ep.outboundQueues[outboundLoopback].Write(filler)
	filler.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { ep.DeliverLoopback(delivering); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		ep.Close()
		<-done
		t.Fatal("loopback consumer blocked writing its reply into its own full queue")
	}
	if got := ep.Read(outboundLoopback); got != filler {
		if got != nil {
			got.DecRef()
		}
		t.Fatalf("Read = %p, want queued packet %p", got, filler)
	} else {
		got.DecRef()
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("queued packet released %d times, want 1", got)
	}
	// Recovery must happen before cancellation or closing the endpoint.
	ep.DeliverLoopback(queueTestACK(queueTestLocalIP, queueTestLocalIP))
	requireQueueTestReset(t, ep, outboundLoopback)
}

func TestHostReplyWithFullWireGuardQueue(t *testing.T) {
	_, ep := newQueueTestStack(t, 1)
	var released atomic.Int32
	filler := newQueueTestPacket(&released)
	err := ep.outboundQueues[outboundToWireGuard].Write(filler)
	filler.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { ep.DeliverLoopback(queueTestACK(queueTestLocalIP, serviceIP)); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		ep.Close()
		<-done
		t.Fatal("full WireGuard queue blocked a host-bound reply")
	}
	requireQueueTestReset(t, ep, outboundToHost)
	if got := ep.outboundQueues[outboundToWireGuard].Num(); got != 1 {
		t.Errorf("WireGuard queue length = %d, want 1", got)
	}
}

func TestCloseWithFullOutboundQueues(t *testing.T) {
	ns := makeNetstack(t, func(ns *Impl) { ns.ProcessLocalIPs = true })
	if err := ns.ipstack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(queueTestLocalIP.As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	laddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(queueTestLocalIP.As4()), Port: 8080}
	ln, err := gonet.ListenTCP(ns.ipstack, laddr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, ns.ipstack, laddr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	// With an established connection, stack shutdown must generate a reset.
	// Stop all readers and fill all three queues before triggering that abort.
	ns.ctxCancel()
	ns.injectWG.Wait()
	var released atomic.Int32
	var queued int32
	for _, q := range ns.linkEP.outboundQueues {
		if q == nil {
			continue
		}
		for range cap(q.c) {
			pkt := newQueueTestPacket(&released)
			err := q.Write(pkt)
			pkt.DecRef()
			if err != nil {
				t.Fatal(err)
			}
			queued++
		}
	}
	done := make(chan struct{})
	go func() { ns.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		ns.linkEP.Close()
		<-done
		t.Fatal("Close blocked with full outbound queues")
	}
	if got := released.Load(); got != queued {
		t.Errorf("released %d queued packets, want %d", got, queued)
	}
}

func TestCloseWithBlockedOutboundInjection(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(fmt.Sprintf("queues=%d", queues), func(t *testing.T) {
			testCloseWithBlockedOutboundInjection(t, queues)
		})
	}
}

func testCloseWithBlockedOutboundInjection(t *testing.T, queues int) {
	// Unlike makeNetstack, this fixture has no WireGuard reader to consume
	// InjectionQueue. Closing netstack must not require closing its Wrapper.
	sys := tsd.NewSystem()
	t.Cleanup(sys.Bus.Get().Close)
	tw := tstun.Wrap(t.Logf, newQueueTestTUN(queues), sys.UserMetricsRegistry(), sys.Bus.Get())
	t.Cleanup(func() { tw.Close() })
	if err := tw.InjectOutbound([]byte{1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ns := &Impl{ctx: ctx, ctxCancel: cancel, tundev: tw, logf: t.Logf}
	ns.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return false })
	ns.atomicIsVIPServiceIPFunc.Store(func(netip.Addr) bool { return false })
	ns.linkEP = newLinkEndpoint(1, 1280, "", groNotSupported, ns.outboundQueueForPacket)
	ns.ipstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := ns.ipstack.CreateNIC(nicID, ns.linkEP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tw.Close(); ns.Close() })
	q := ns.linkEP.outboundQueues[outboundToWireGuard]
	var released atomic.Int32
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{1}), OnRelease: func() { released.Add(1) },
	})
	err := q.Write(pkt)
	pkt.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	tw.Start()
	nativeReadDone := make(chan error, queues)
	for _, q := range tw.Queues()[:queues] {
		go func() {
			slab := make([]byte, tstun.MaxPacketSize+2*tun.ReadPacketSpacing)
			_, err := q.Read(slab, make([]tun.ReadPacket, 1))
			nativeReadDone <- err
		}()
	}
	ns.injectWG.Go(ns.injectToWireGuard)
	if err := tstest.WaitFor(time.Second, func() error {
		if q.Num() != 0 {
			return fmt.Errorf("injector has not dequeued packet")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { ns.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		tw.Close()
		<-done
		t.Fatal("netstack Close required closing the Wrapper to cancel injection")
	}
	if got := released.Load(); got != 1 {
		t.Errorf("canceled packet released %d times, want 1", got)
	}
	// The shared Wrapper must remain usable after netstack stops injecting.
	slab := make([]byte, tstun.MaxPacketSize+2*tun.ReadPacketSpacing)
	if n, err := tw.InjectionQueue().Read(slab, make([]tun.ReadPacket, 1)); n != 1 || err != nil {
		t.Fatalf("Read after netstack Close = %d, %v", n, err)
	}
	if err := tw.InjectOutbound([]byte{2}); err != nil {
		t.Fatalf("InjectOutbound after netstack Close: %v", err)
	}
	select {
	case err := <-nativeReadDone:
		t.Fatalf("netstack Close terminated a native queue reader: %v", err)
	default:
	}
	tw.Close()
	for range queues {
		select {
		case err := <-nativeReadDone:
			if err != io.EOF {
				t.Errorf("native read after Wrapper Close = %v, want EOF", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Wrapper Close did not release a native queue reader")
		}
	}
}

func TestInjectToWireGuardStopsOnClosedWrapper(t *testing.T) {
	sys := tsd.NewSystem()
	t.Cleanup(sys.Bus.Get().Close)
	tw := tstun.Wrap(t.Logf, tstun.NewFake(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ep := newLinkEndpoint(1, 1280, "", groNotSupported, nil)
	defer ep.Close()
	var released atomic.Int32
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{1}), OnRelease: func() { released.Add(1) },
	})
	err := ep.outboundQueues[outboundToWireGuard].Write(pkt)
	pkt.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	ns := &Impl{ctx: ctx, tundev: tw, linkEP: ep, logf: t.Logf}
	done := make(chan struct{})
	go func() { ns.injectToWireGuard(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("injectToWireGuard did not stop on a closed Wrapper")
	}
	if ctx.Err() != nil {
		t.Fatal("netstack context should still be active")
	}
	if got := released.Load(); got != 1 {
		t.Errorf("rejected packet released %d times, want 1", got)
	}
}

func startQueueTestLoopbackConsumer(t testing.TB, ep *linkEndpoint) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			pkt := ep.ReadContext(ctx, outboundLoopback)
			if pkt == nil {
				return
			}
			ep.DeliverLoopback(pkt)
		}
	}()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	return stop
}

// Full-queue loss must not corrupt TCP data or permanently stop delivery.
// Stop the real loopback consumer, force data-packet rejection, then resume
// delivery and verify gVisor retransmits all bytes without changing them.
func TestTCPTransferAfterQueueDrops(t *testing.T) {
	s, ep := newQueueTestStack(t, 8)
	q := ep.outboundQueues[outboundLoopback]
	dropped := make(chan struct{})
	var dropOnce sync.Once
	router := ep.outboundQueueRouter
	ep.outboundQueueRouter = func(pkt *stack.PacketBuffer) outboundQueue {
		dest := router(pkt)
		if dest == outboundLoopback && pkt.Data().Size() != 0 && q.Num() == cap(q.c) {
			// With the consumer stopped and every slot occupied, this write
			// must be rejected. Observe an actual data packet, not a filler.
			dropOnce.Do(func() { close(dropped) })
		}
		return dest
	}
	stop := startQueueTestLoopbackConsumer(t, ep)
	addr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(queueTestLocalIP.As4()), Port: 8080}
	ln, err := gonet.ListenTCP(s, addr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, s, addr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	stop()
	// Finish any handshake traffic still in the queue before adding fillers.
	for pkt := q.Read(); pkt != nil; pkt = q.Read() {
		ep.DeliverLoopback(pkt)
	}
	var released atomic.Int32
	for range cap(q.c) {
		pkt := newQueueTestPacket(&released)
		err := q.Write(pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	want := bytes.Repeat([]byte("TCP queue recovery\x00"), 256)
	written := make(chan error, 1)
	go func() {
		n, err := c.Write(want)
		if err == nil && n != len(want) {
			err = fmt.Errorf("Write = %d, want %d", n, len(want))
		}
		written <- err
	}()
	select {
	case <-dropped:
	case <-time.After(2 * time.Second):
		ep.Close()
		<-written
		t.Fatal("TCP did not attempt to send into the full queue")
	}
	// Write sends inline in gVisor. Wait for it to finish while the queue
	// is still full, so observing the classifier cannot race with freeing a
	// slot and accidentally turn the intended rejection into an acceptance.
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		ep.Close()
		<-written
		t.Fatal("TCP Write blocked on a full queue")
	}
	for pkt := q.Read(); pkt != nil; pkt = q.Read() {
		pkt.DecRef()
	}
	if got := released.Load(); got != int32(cap(q.c)) {
		t.Fatalf("released %d fillers, want %d", got, cap(q.c))
	}
	startQueueTestLoopbackConsumer(t, ep)
	if err := sc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("TCP data changed after queue drops and retransmissions")
	}
}

// BenchmarkTCPQueueTransfer measures sustained in-memory TCP over the real
// loopback link at the production queue size. It excludes WireGuard and OS I/O;
// it is not a claim about end-to-end VPN throughput or overload behavior.
func BenchmarkTCPQueueTransfer(b *testing.B) {
	for _, size := range []int{4 << 10, 256 << 10} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			s, ep := newQueueTestStack(b, 512)
			startQueueTestLoopbackConsumer(b, ep)
			addr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(queueTestLocalIP.As4()), Port: 8080}
			ln, err := gonet.ListenTCP(s, addr, header.IPv4ProtocolNumber)
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, s, addr, header.IPv4ProtocolNumber)
			if err != nil {
				b.Fatal(err)
			}
			defer c.Close()
			sc, err := ln.Accept()
			if err != nil {
				b.Fatal(err)
			}
			defer sc.Close()
			data := bytes.Repeat([]byte{0x55}, size)
			requests := make(chan struct{})
			written := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for range requests {
					n, err := c.Write(data)
					if err == nil && n != len(data) {
						err = io.ErrShortWrite
					}
					written <- err
				}
			}()
			defer func() { close(requests); c.Close(); <-done }()
			got := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				requests <- struct{}{}
				if _, err := io.ReadFull(sc, got); err != nil {
					b.Fatal(err)
				}
				if err := <-written; err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
