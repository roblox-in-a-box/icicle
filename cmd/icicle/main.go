package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"icicle/internal/broker"
)

func main() { os.Exit(run()) }

func run() int {
	addr := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()
	b := broker.New(broker.Config{})
	server := &http.Server{
		Addr:              *addr,
		Handler:           b,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() {
		log.Printf("Icicle listening on %s", *addr)
		result <- server.ListenAndServe()
	}()
	select {
	case err := <-result:
		b.Close()
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server_failed reason=%q", err)
			return 1
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
		b.Close()
	}
	return 0
}
