package main

import (
	"context"
	"flag"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/config"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

const (
	defaultName = "world"
)

var (
	name = flag.String("name", defaultName, "Name to greet")

	identity = flag.String("identity", "", "Ziti Identity file")
	service  = flag.String("service", "", "Ziti Service")
)

func main() {
	flag.Parse()
	cfg, err := config.NewFromFile(*identity)
	if err != nil {
		log.Fatalf("failed to load config err=%v", err)
	}

	ztx := ziti.NewContextWithConfig(cfg)
	err = ztx.Authenticate()
	if err != nil {
		log.Fatalf("failed to authenticate: %v", err)
	}
	// Set up a connection to the server.
	conn, err := grpc.Dial(*service,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return ztx.Dial(s)
		}),
	)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: *name})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetMessage())
}
