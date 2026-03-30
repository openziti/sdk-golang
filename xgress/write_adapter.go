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

import "time"

func NewWriteAdapter(x *Xgress) *WriteAdapter {
	result := &WriteAdapter{
		x: x,
	}
	result.init(&x.payloadBuffer.writeDeadlineCb, x.payloadBuffer.events)
	return result
}

type WriteAdapter struct {
	deadlineControl
	x *Xgress
}

func (self *WriteAdapter) Deadline() (deadline time.Time, ok bool) {
	deadline = self.deadline.Load()
	return deadline, !deadline.IsZero()
}

func (self *WriteAdapter) Err() error {
	return nil
}

func (self *WriteAdapter) Value(any) any {
	return nil
}

func (self *WriteAdapter) SetWriteDeadline(t time.Time) error {
	return self.SetDeadline(t)
}

func (self *WriteAdapter) Write(b []byte) (n int, err error) {
	if err = self.x.Write(b, nil, self); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (self *WriteAdapter) WriteToXgress(b []byte, header map[uint8][]byte) (n int, err error) {
	if err = self.x.Write(b, header, self); err != nil {
		return 0, err
	}
	return len(b), nil
}
