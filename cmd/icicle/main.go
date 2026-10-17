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
	keyPath := flag.String("authority-key", "icicle-authority.key", "Persistent ticket signing key file")
	adminPath := flag.String("admin-keys", "", "File containing one admin UniqueUserId per line")
	flag.Parse()
	key, err := broker.LoadAuthority(*keyPath)
	if err != nil {
		log.Printf("authority_key_failed reason=%q", err)
		return 1
	}
	config := broker.Config{SigningKey: key}
	if *adminPath != "" {
		data, err := os.ReadFile(*adminPath)
		if err != nil {
			log.Printf("admin_keys_failed reason=%q", err)
			return 1
		}
		config.AdminKeys, err = broker.ParseAdminKeys(string(data))
		if err != nil {
			log.Printf("admin_keys_failed reason=%q", err)
			return 1
		}
	}
	b, err := broker.New(config)
	if err != nil {
		log.Printf("broker_failed reason=%q", err)
		return 1
	}
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
