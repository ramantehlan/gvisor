// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

func TestPacketHeaderPush(t *testing.T) {
	for _, test := range []struct {
		name      string
		reserved  int
		link      []byte
		network   []byte
		transport []byte
		data      []byte
	}{
		{
			name: "construct empty packet",
		},
		{
			name:     "construct link header only packet",
			reserved: 60,
			link:     makeView(10),
		},
		{
			name:     "construct link and network header only packet",
			reserved: 60,
			link:     makeView(10),
			network:  makeView(20),
		},
		{
			name:      "construct header only packet",
			reserved:  60,
			link:      makeView(10),
			network:   makeView(20),
			transport: makeView(30),
		},
		{
			name: "construct data only packet",
			data: makeView(40),
		},
		{
			name:      "construct L3 packet",
			reserved:  60,
			network:   makeView(20),
			transport: makeView(30),
			data:      makeView(40),
		},
		{
			name:      "construct L2 packet",
			reserved:  60,
			link:      makeView(10),
			network:   makeView(20),
			transport: makeView(30),
			data:      makeView(40),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Make a copy of data to make sure our truth data won't be taint by
			// PacketBuffer.
			dataCopy := append(buffer.View(nil), test.data...)

			pk := NewPacketBuffer(&NewPacketBufferOptions{
				ReserveHeaderBytes: test.reserved,
				Data:               dataCopy.ToVectorisedView(),
			})

			allHdrSize := len(test.link) + len(test.network) + len(test.transport)

			// Check the initial values for packet.
			checkInitialPacketBuffer(t, pk, &NewPacketBufferOptions{
				ReserveHeaderBytes: test.reserved,
				Data:               buffer.View(test.data).ToVectorisedView(),
			})

			// Push headers.
			if v := test.transport; len(v) > 0 {
				copy(pk.TransportHeader().Push(len(v)), v)
			}
			if v := test.network; len(v) > 0 {
				copy(pk.NetworkHeader().Push(len(v)), v)
			}
			if v := test.link; len(v) > 0 {
				copy(pk.LinkHeader().Push(len(v)), v)
			}

			// Check the after values for packet.
			if got, want := pk.ReservedHeaderBytes(), test.reserved; got != want {
				t.Errorf("After pk.ReservedHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.AvailableHeaderBytes(), test.reserved-allHdrSize; got != want {
				t.Errorf("After pk.AvailableHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.Size(), allHdrSize+len(test.data); got != want {
				t.Errorf("After pk.Size() = %d, want %d", got, want)
			}
			checkViewEqual(t, "After pk.Data.Views()", concatViews(pk.Data.Views()...), test.data)
			checkViewEqual(t, "After pk.Views()", concatViews(pk.Views()...),
				concatViews(test.link, test.network, test.transport, test.data))
			// Check the after values for each header.
			checkPacketHeader(t, "After pk.LinkHeader", pk.LinkHeader(), test.link)
			checkPacketHeader(t, "After pk.NetworkHeader", pk.NetworkHeader(), test.network)
			checkPacketHeader(t, "After pk.TransportHeader", pk.TransportHeader(), test.transport)
			// Check the after values for PayloadSince.
			checkViewEqual(t, "After PayloadSince(LinkHeader)",
				PayloadSince(pk.LinkHeader()),
				concatViews(test.link, test.network, test.transport, test.data))
			checkViewEqual(t, "After PayloadSince(NetworkHeader)",
				PayloadSince(pk.NetworkHeader()),
				concatViews(test.network, test.transport, test.data))
			checkViewEqual(t, "After PayloadSince(TransportHeader)",
				PayloadSince(pk.TransportHeader()),
				concatViews(test.transport, test.data))
		})
	}
}

func TestPacketHeaderConsume(t *testing.T) {
	for _, test := range []struct {
		name      string
		data      []byte
		link      int
		network   int
		transport int
	}{
		{
			name:      "parse L2 packet",
			data:      concatViews(makeView(10), makeView(20), makeView(30), makeView(40)),
			link:      10,
			network:   20,
			transport: 30,
		},
		{
			name:      "parse L3 packet",
			data:      concatViews(makeView(20), makeView(30), makeView(40)),
			network:   20,
			transport: 30,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Make a copy of data to make sure our truth data won't be taint by
			// PacketBuffer.
			dataCopy := append(buffer.View(nil), test.data...)

			pk := NewPacketBuffer(&NewPacketBufferOptions{
				Data: dataCopy.ToVectorisedView(),
			})

			// Check the initial values for packet.
			checkInitialPacketBuffer(t, pk, &NewPacketBufferOptions{
				Data: buffer.View(test.data).ToVectorisedView(),
			})

			// Consume headers.
			if size := test.link; size > 0 {
				if _, ok := pk.LinkHeader().Consume(size); !ok {
					t.Fatalf("pk.LinkHeader().Consume() = false, want true")
				}
			}
			if size := test.network; size > 0 {
				if _, ok := pk.NetworkHeader().Consume(size); !ok {
					t.Fatalf("pk.NetworkHeader().Consume() = false, want true")
				}
			}
			if size := test.transport; size > 0 {
				if _, ok := pk.TransportHeader().Consume(size); !ok {
					t.Fatalf("pk.TransportHeader().Consume() = false, want true")
				}
			}

			allHdrSize := test.link + test.network + test.transport

			// Check the after values for packet.
			if got, want := pk.ReservedHeaderBytes(), 0; got != want {
				t.Errorf("After pk.ReservedHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.AvailableHeaderBytes(), 0; got != want {
				t.Errorf("After pk.AvailableHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.Size(), len(test.data); got != want {
				t.Errorf("After pk.Size() = %d, want %d", got, want)
			}
			// After state of pk.
			var (
				link      = test.data[:test.link]
				network   = test.data[test.link:][:test.network]
				transport = test.data[test.link+test.network:][:test.transport]
				payload   = test.data[allHdrSize:]
			)
			checkViewEqual(t, "After pk.Data.Views()", concatViews(pk.Data.Views()...), payload)
			checkViewEqual(t, "After pk.Views()", concatViews(pk.Views()...), test.data)
			// Check the after values for each header.
			checkPacketHeader(t, "After pk.LinkHeader", pk.LinkHeader(), link)
			checkPacketHeader(t, "After pk.NetworkHeader", pk.NetworkHeader(), network)
			checkPacketHeader(t, "After pk.TransportHeader", pk.TransportHeader(), transport)
			// Check the after values for PayloadSince.
			checkViewEqual(t, "After PayloadSince(LinkHeader)",
				PayloadSince(pk.LinkHeader()),
				concatViews(link, network, transport, payload))
			checkViewEqual(t, "After PayloadSince(NetworkHeader)",
				PayloadSince(pk.NetworkHeader()),
				concatViews(network, transport, payload))
			checkViewEqual(t, "After PayloadSince(TransportHeader)",
				PayloadSince(pk.TransportHeader()),
				concatViews(transport, payload))
		})
	}
}

func checkInitialPacketBuffer(t *testing.T, pk *PacketBuffer, opts *NewPacketBufferOptions) {
	t.Helper()
	reserved := opts.ReserveHeaderBytes
	if got, want := pk.ReservedHeaderBytes(), reserved; got != want {
		t.Errorf("Initial pk.ReservedHeaderBytes() = %d, want %d", got, want)
	}
	if got, want := pk.AvailableHeaderBytes(), reserved; got != want {
		t.Errorf("Initial pk.AvailableHeaderBytes() = %d, want %d", got, want)
	}
	data := opts.Data.ToView()
	if got, want := pk.Size(), len(data); got != want {
		t.Errorf("Initial pk.Size() = %d, want %d", got, want)
	}
	checkViewEqual(t, "Initial pk.Data.Views()", concatViews(pk.Data.Views()...), data)
	checkViewEqual(t, "Initial pk.Views()", concatViews(pk.Views()...), data)
	// Check the initial values for each header.
	checkPacketHeader(t, "Initial pk.LinkHeader", pk.LinkHeader(), nil)
	checkPacketHeader(t, "Initial pk.NetworkHeader", pk.NetworkHeader(), nil)
	checkPacketHeader(t, "Initial pk.TransportHeader", pk.TransportHeader(), nil)
	// Check the initial valies for PayloadSince.
	checkViewEqual(t, "Initial PayloadSince(LinkHeader)",
		PayloadSince(pk.LinkHeader()), data)
	checkViewEqual(t, "Initial PayloadSince(NetworkHeader)",
		PayloadSince(pk.NetworkHeader()), data)
	checkViewEqual(t, "Initial PayloadSince(TransportHeader)",
		PayloadSince(pk.TransportHeader()), data)
}

func checkPacketHeader(t *testing.T, name string, h PacketHeader, want []byte) {
	t.Helper()
	if got, want := len(h.View()), len(want); got != want {
		t.Errorf("len(%s.View()) = %d, want %d", name, got, want)
	}
	checkViewEqual(t, name+".View()", h.View(), want)
}

func checkViewEqual(t *testing.T, what string, got buffer.View, want buffer.View) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s = %x, want %x", what, got, want)
	}
}

func makeView(size int) buffer.View {
	b := byte(size)
	return bytes.Repeat([]byte{b}, size)
}

func concatViews(views ...buffer.View) buffer.View {
	var all buffer.View
	for _, v := range views {
		all = append(all, v...)
	}
	return all
}
