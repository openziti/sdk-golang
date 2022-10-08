package cmd

import (
	"bufio"
	"fmt"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"net"
	"os"
	"strings"
)

func Server(zitiCfg *config.Config, serviceName string) {
	listener, err := ziti.NewContextWithConfig(zitiCfg).Listen(serviceName)
	if err != nil {
		log.Panic(err)
	}
	serve(listener)

	sig := make(chan os.Signal)
	s := <-sig
	log.Infof("received %s: shutting down...", s)
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
