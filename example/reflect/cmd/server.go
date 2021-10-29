package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	// Create a summary to track fictional interservice RPC latencies for three
	// distinct services with different latency distributions. These services are
	// differentiated via a "service" label.
	connections = prometheus.NewCounter(prometheus.CounterOpts(prometheus.Opts{
		Namespace: "reflect",
		Name:      "total_connections",
		Help:      "number of connections established",
	}))
)

func init() {
	prometheus.MustRegister(connections)
	prometheus.MustRegister(collectors.NewBuildInfoCollector())
}

func Server(zitiCfg *config.Config, serviceName string) {
	listener, err := ziti.NewContextWithConfig(zitiCfg).Listen(serviceName)
	if err != nil {
		log.Panic(err)
	}
	serve(listener)

	sig := make(chan os.Signal)
	select {
	case s := <-sig:
		log.Infof("received %s: shutting down...", s)
	}
}

func serve(listener net.Listener) {
	log.Infof("ready to accept connections")
	for {
		conn, _ := listener.Accept()
		log.Infof("new connection accepted")
		go accept(conn)
	}
}

func accept(conn net.Conn) {
	if conn == nil {
		panic("connection is nil!")
	}
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)
	rw := bufio.NewReadWriter(reader, writer)
	//line delimited
	connections.Inc()
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			log.Error(err)
			break
		}
		log.Info("about to read a string :")
		log.Infof("                  read : %s", strings.TrimSpace(line))
		resp := fmt.Sprintf("you sent me: %s", line)
		_, _ = rw.WriteString(resp)
		_ = rw.Flush()
		log.Infof("       responding with : %s", strings.TrimSpace(resp))
	}
}
