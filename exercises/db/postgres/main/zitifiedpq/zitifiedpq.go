package zitifiedpq

import (
	"database/sql"
	"database/sql/driver"
	"github.com/lib/pq"
	"net"
	"time"
)

//from https://github.com/lib/pq/issues/470
type drvWrapper struct{}

func (d drvWrapper) Open(name string) (driver.Conn, error) {
	return pq.DialOpen(drvWrapper{}, name)
}

func (d drvWrapper) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (d drvWrapper) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

func init() {
	sql.Register("zitifiedPostgresDriver", drvWrapper{})
}
