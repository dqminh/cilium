package ctmap

import (
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/common/types"
	"bytes"
	"fmt"
)

type CtKey4 struct {
       addr    types.IPv4
       sport   uint16
       dport   uint16
       nexthdr u8proto.U8proto
       flags   uint8
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