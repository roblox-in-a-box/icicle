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
	"icicle/internal/relay"
)

func main() { os.Exit(run()) }

func run() int {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	addr := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	keyPath := flag.String("authority-key", "icicle-authority.key", "Ticket signing key file, generated if missing")
	configPath := flag.String("config", "config.json", `Config file with {"Admins":{"ed25519:public-key":true}}, optional by default`)
	flag.Parse()
	configRequired := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configRequired = true
		}
	})
	settings, err := loadConfig(*configPath, configRequired)
	if err != nil {
		log.Printf("config_failed reason=%q", err)
		return 1
	}
	admins, err := broker.ParseAdminKeys(settings.Admins)
	if err != nil {
		log.Printf("config_failed reason=%q", err)
		return 1
	}
	key, err := broker.LoadAuthority(*keyPath)
	if err != nil {
		log.Printf("authority_key_failed reason=%q", err)
		return 1
	}
	var turnServer *relay.Server
	if settings.TURN != nil {
		turnServer, err = relay.New(*settings.TURN)
		if err != nil {
			log.Printf("turn_failed reason=%q", err)
			return 1
		}
		defer turnServer.Close()
	}
	b, err := broker.New(broker.Config{SigningKey: key, AdminKeys: admins, Relay: turnServer, TrustLoopbackProxy: settings.TrustLoopbackProxy})
	if err != nil {
		log.Printf("broker_failed reason=%q", err)
		return 1
	}
	log.Printf("broker_ready listen=%q config=%q authority_key=%q admins=%d registration_timeout_seconds=35 admission_timeout_seconds=90 turn_udp=%t websocket_relay=true", *addr, *configPath, *keyPath, len(admins), settings.TURN != nil && settings.TURN.UDPListen != "")
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
		log.Printf("server_stopping reason=%q", ctx.Err())
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
		b.Close()
	}
	return 0
}
