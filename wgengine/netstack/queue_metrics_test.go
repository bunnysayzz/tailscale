// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/usermetric"
)

func TestOutboundQueueFullMetrics(t *testing.T) {
	for _, destination := range []outboundQueue{outboundToWireGuard, outboundToHost, outboundLoopback} {
		for _, size := range []int{0, 1} {
			t.Run(fmt.Sprintf("queue=%d/size=%d", destination, size), func(t *testing.T) {
				ep := newLinkEndpoint(size, 1280, "", groNotSupported, func(*stack.PacketBuffer) outboundQueue { return destination })
				t.Cleanup(ep.Close)
				ns := &Impl{linkEP: ep, ipstack: stack.New(stack.Options{})}
				t.Cleanup(func() { ns.ipstack.Close(); ns.ipstack.Wait() })
				stacksForMetrics.Store(ns, struct{}{})
				t.Cleanup(func() { stacksForMetrics.Delete(ns) })
				var reg usermetric.Registry
				ns.SetMetricsRegistry(&reg)
				// Obtain the debug view before changing the counter to ensure it
				// and the registry expose the live value, not a snapshot.
				debug := ns.ExpVar()

				var released atomic.Int32
				var pkts stack.PacketBufferList
				for range 4 {
					pkts.PushBack(newQueueTestPacket(&released))
				}
				n, err := ep.WritePackets(pkts)
				pkts.DecRef()
				if n != size || err != nil {
					t.Fatalf("WritePackets = %d, %v; want %d, nil", n, err, size)
				}
				want := int64(4 - size)
				if got := ep.outboundQueueFullDropped.Value(); got != want {
					t.Fatalf("queue-full drops = %d, want %d", got, want)
				}
				if got := released.Load(); int64(got) != want {
					t.Errorf("released = %d, want %d", got, want)
				}
				if !strings.Contains(debug.String(), fmt.Sprintf("\"counter_outbound_queue_full_dropped_packets\": %d", want)) {
					t.Errorf("debug metrics missing drop count: %s", debug.String())
				}
				if buildfeatures.HasUserMetrics {
					rr := httptest.NewRecorder()
					reg.Handler(rr, httptest.NewRequest("GET", "/metrics", nil))
					if !strings.Contains(rr.Body.String(), fmt.Sprintf("tailscaled_netstack_outbound_queue_full_dropped_packets_total{} %d\n", want)) {
						t.Errorf("user metrics missing drop count: %s", rr.Body.String())
					}
				}
				if buildfeatures.HasClientMetrics {
					// Client metrics aggregate the same per-endpoint counters
					// across all netstacks in the process.
					other := &Impl{linkEP: newLinkEndpoint(0, 1280, "", groNotSupported, nil), ipstack: ns.ipstack}
					other.linkEP.outboundQueueFullDropped.Add(2)
					stacksForMetrics.Store(other, struct{}{})
					t.Cleanup(func() { stacksForMetrics.Delete(other); other.linkEP.Close() })
					var b bytes.Buffer
					clientmetric.WritePrometheusExpositionFormat(&b)
					if !strings.Contains(b.String(), fmt.Sprintf("netstack_outbound_queue_full_dropped_packets %d\n", want+2)) {
						t.Errorf("client metrics missing drop count: %s", b.String())
					}
				}

				// Shutdown loss is not queue-full loss.
				ep.Close()
				pkt := newQueueTestPacket(&released)
				var closedPkts stack.PacketBufferList
				closedPkts.PushBack(pkt)
				n, err = ep.WritePackets(closedPkts)
				closedPkts.DecRef()
				if _, ok := err.(*tcpip.ErrClosedForSend); !ok || n != 0 {
					t.Errorf("closed WritePackets = %d, %v", n, err)
				}
				if got := ep.outboundQueueFullDropped.Value(); got != want {
					t.Errorf("closed write changed queue-full drops to %d, want %d", got, want)
				}
			})
		}
	}
}
