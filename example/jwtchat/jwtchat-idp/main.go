package main

import (
	"context"
	"github.com/openziti/sdk-golang/example/jwtchat/jwtchat-idp/exampleop"
	"github.com/openziti/sdk-golang/example/jwtchat/jwtchat-idp/storage"
	"log"
	"net/http"
)

func main() {
	ctx := context.Background()

	storage := storage.NewStorage(storage.NewUserStore())

	port := "9998"
	router := exampleop.SetupServer(ctx, "http://localhost:"+port, storage)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}
	log.Printf("server listening on http://localhost:%s/", port)
	log.Println("press ctrl+c to stop")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
}
