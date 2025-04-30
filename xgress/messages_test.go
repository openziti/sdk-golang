/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package xgress

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"sync/atomic"
	"testing"
)

// A simple test to check for failure of alignment on atomic operations for 64 bit variables in a struct
func Test64BitAlignment(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("One of the variables that was tested is not properly 64-bit aligned.")
		}
	}()

	lsb := Xgress{}
	tPayload := txPayload{}
	reTx := Retransmitter{}

	atomic.LoadInt64(&lsb.timeOfLastRxFromLink)
	atomic.LoadInt64(&tPayload.age)
	atomic.LoadInt64(&reTx.retransmitsQueueSize)
}

func TestSetOriginatorFlag(t *testing.T) {
	type args struct {
		flags      uint32
		originator Originator
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{

		{name: "set empty to ingress",
			args: args{
				flags:      0,
				originator: Initiator,
			},
			want: 0,
		},
		{name: "set end of circuit to ingress",
			args: args{
				flags:      uint32(PayloadFlagCircuitEnd),
				originator: Initiator,
			},
			want: uint32(PayloadFlagCircuitEnd),
		},
		{name: "set empty to egress",
			args: args{
				flags:      0,
				originator: Terminator,
			},
			want: uint32(PayloadFlagOriginator),
		},
		{name: "set end of circuit to egress",
			args: args{
				flags:      uint32(PayloadFlagCircuitEnd),
				originator: Terminator,
			},
			want: uint32(PayloadFlagCircuitEnd) | uint32(PayloadFlagOriginator),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SetOriginatorFlag(tt.args.flags, tt.args.originator); got != tt.want {
				t.Errorf("SetOriginatorFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAcknowledgement_marshallSequence(t *testing.T) {
	tests := []struct {
		name     string
		sequence []int32
	}{

		{name: "nil", sequence: nil},
		{name: "empty", sequence: make([]int32, 0)},
		{name: "one entry", sequence: []int32{1}},
		{name: "many entries", sequence: []int32{1, -1, 100, 200, -3213232, 421123, -58903204, -4324, 432432, 0, 9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ack := &Acknowledgement{
				Sequence: tt.sequence,
			}
			got := ack.marshallSequence()
			ack2 := &Acknowledgement{}
			err := ack2.unmarshallSequence(got)
			assert.NoError(t, err)

			if len(ack.Sequence) == 0 {
				return
			}
			if !reflect.DeepEqual(ack, ack2) {
				t.Errorf("marshallSequence() = %v, want %v", ack2, ack)
			}
		})
	}
}
