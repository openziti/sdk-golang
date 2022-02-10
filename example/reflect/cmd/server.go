package cmd

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// prometheus metric to track the total number of connections established
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

func Server(zitiCfg *config.Config, serviceName string, prometheusServiceName string) {
	// if no prometheusServiceName was provided, don't attempt to serve the metrics end point
	if prometheusServiceName != "" {
		go serverPrometheusCollector(zitiCfg, prometheusServiceName)
	}

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

// function for exposing the prometheus metrics over ziti
func serverPrometheusCollector(zitiCfg *config.Config, prometheusServiceName string) {
	options := &ziti.ListenOptions{
		ConnectTimeout:        5 * time.Minute,
		MaxConnections:        3,
		BindUsingEdgeIdentity: true,
	}

	listener, err := ziti.NewContextWithConfig(zitiCfg).ListenWithOptions(prometheusServiceName, options)
	if err != nil {
		log.Fatalf("failed to create a listener: %v", err)
	}

	log.Fatal(http.Serve(listener, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	)))
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
