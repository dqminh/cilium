// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctmap

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/u8proto"
)

type CtMap struct {
	path string
	Fd   int
	Type CtType
}

// ServiceKey is the interface describing protocol independent key for services map.
type ServiceKey interface {
	bpf.MapKey

	// Returns human readable string representation
	String() string

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Returns the BPF Weighted Round Robin map matching the key type
	//RRMap() *bpf.Map

	// Returns a RevNatValue matching a ServiceKey
	//RevNatValue() RevNatValue

	// Returns the source port set in the key or 0
	GetSrcPort() uint16

	// Returns the destination port set in the key or 0
	GetDstPort() uint16

	// Returns the next header
	GetNextHdr() u8proto.U8proto

	// Returns the flags
	GetFlags() uint8


	// Set the backend index (master: 0, backend: nth backend)
	//SetBackend(int)

	// Return backend index
	//GetBackend() int

	// Convert between host byte order and map byte order
	Convert() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map.
type ServiceValue interface {
	bpf.MapValue

	// Returns human readable string representation
	String() string

	// Returns a RevNatKey matching a ServiceValue
	//RevNatKey() RevNatKey

	// Set the number of backends
	//SetCount(int)

	// Get the number of backends
	//GetCount() int

	// Set address to map to (left blank for master)
	//SetAddress(net.IP) error

	// Set source port to map to (left blank for master)
	SetSrcPort(uint16)

	//Set destination port to map to (left blank for master)
	SetDstPort(uint16)

	// Sets the next header
	SetNextHdr(u8proto.U8proto)

	// Sets the flags
	SetFlags(uint8)

	// Set reverse NAT identifier
	//SetRevNat(int)

	// Set Weight
	//SetWeight(uint16)

	// Get Weight
	//GetWeight() uint16

	// Convert between host byte order and map byte order
	Convert() ServiceValue
}

const (
	MapName6 = "cilium_ct6_"
	MapName4 = "cilium_ct4_"

	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
)

type CtKey interface {
	Dump(buffer *bytes.Buffer) bool
}

func (key CtKey6) Dump(buffer *bytes.Buffer) bool {
	if key.nexthdr == 0 {
		return false
	}

	if key.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.sport, key.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.dport,
			key.sport),
		)
	}

	if key.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}

func (key CtKey4) Dump(buffer *bytes.Buffer) bool {
	if key.nexthdr == 0 {
		return false
	}

	if key.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.sport, key.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.dport,
			key.sport),
		)
	}

	if key.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}

type CtEntry struct {
	rx_packets uint64
	rx_bytes   uint64
	tx_packets uint64
	tx_bytes   uint64
	lifetime   uint16
	flags      uint16
	revnat     uint16
	proxy_port uint16
}

type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}

func (m *CtMap) String() string {
	return m.path
}

func (m *CtMap) Dump() (string, error) {
	var buffer bytes.Buffer
	entries, err := m.DumpToSlice()
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Key.Dump(&buffer) {
			continue
		}

		value := entry.Value
		buffer.WriteString(
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d\n",
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				common.Swab16(value.revnat),
				common.Swab16(value.proxy_port)),
		)

	}
	return buffer.String(), nil
}

func (m *CtMap) DumpToSlice() ([]CtEntryDump, error) {
	var entry CtEntry
	entries := []CtEntryDump{}

	switch m.Type {
	case CtTypeIPv6:
		var key, nextKey CtKey6
		for {
			err := bpf.GetNextKey(m.Fd, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
			if err != nil {
				break
			}

			err = bpf.LookupElement(
				m.Fd,
				unsafe.Pointer(&nextKey),
				unsafe.Pointer(&entry),
			)
			if err != nil {
				return nil, err
			}

			eDump := CtEntryDump{Key: nextKey, Value: entry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case CtTypeIPv4:
		var key, nextKey CtKey4
		for {
			err := bpf.GetNextKey(m.Fd, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
			if err != nil {
				break
			}

			err = bpf.LookupElement(
				m.Fd,
				unsafe.Pointer(&nextKey),
				unsafe.Pointer(&entry),
			)
			if err != nil {
				return nil, err
			}

			eDump := CtEntryDump{Key: nextKey, Value: entry}
			entries = append(entries, eDump)

			key = nextKey
		}
	}

	return entries, nil
}

func (m *CtMap) doGc(interval uint16, key unsafe.Pointer, nextKey unsafe.Pointer, deleted *int) bool {
	var entry CtEntry

	err := bpf.GetNextKey(m.Fd, key, nextKey)
	if err != nil {
		return false
	}

	err = bpf.LookupElement(m.Fd, nextKey, unsafe.Pointer(&entry))
	if err != nil {
		return false
	}

	if entry.lifetime <= interval {
		bpf.DeleteElement(m.Fd, nextKey)
		(*deleted)++
	} else {
		entry.lifetime -= interval
		bpf.UpdateElement(m.Fd, nextKey, unsafe.Pointer(&entry), 0)
	}

	return true
}

func (m *CtMap) GC(interval uint16) int {
	deleted := 0

	switch m.Type {
	case CtTypeIPv6:
		var key, nextKey CtKey6
		for m.doGc(interval, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), &deleted) {
			key = nextKey
		}
	case CtTypeIPv4:
		var key, nextKey CtKey4
		for m.doGc(interval, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), &deleted) {
			key = nextKey
		}
	}

	return deleted
}
