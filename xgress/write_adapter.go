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
