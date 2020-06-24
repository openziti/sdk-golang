package cmd

import (
	"bufio"
	"fmt"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"net"
	"os"
)

func Server(zitiCfg *config.Config, serviceName string){
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
	for{
		conn, _ :=listener.Accept()
		log.Infof("new connection accepted")
		go accept(conn)
	}
}

func accept(conn net.Conn){
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)
	rw := bufio.NewReadWriter(reader, writer)
	//line delimited
	for {
		log.Info("about to read a string")
		line, err := rw.ReadString('\n')
		if err != nil {
			log.Error(err)
			break
		}
		log.Infof("read a string: %s", line)
		_, _ = rw.WriteString(fmt.Sprintf("you sent me: %s", line))
		_ = rw.Flush()
		log.Info("response sent")
	}
}
