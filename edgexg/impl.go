package edgexg

import (
	"github.com/openziti/sdk-golang/v2/pb/edge_client_pb"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

const (
	// PayloadFlagsHeader is the xgress passthrough header key that carries the edge message flags.
	PayloadFlagsHeader = uint8(edge_client_pb.XgHeaderKey_EdgeFlags)
)

// HeadersToFabric tracks the headers to pass through fabric to the other side
var HeadersToFabric = map[int32]uint8{
	edge.FlagsHeader: PayloadFlagsHeader,
}

var HeadersFromFabric = map[uint8]int32{
	PayloadFlagsHeader: edge.FlagsHeader,
}
