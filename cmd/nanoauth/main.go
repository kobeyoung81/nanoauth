package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"gitee.com/kobeyoung81/nanoauth/internal/config"
	"gitee.com/kobeyoung81/nanoauth/internal/server"
)

func main() {
	cfg := config.DefaultConfig()

	if addr := os.Getenv("NANOAUTH_ADDR"); addr != "" {
		cfg.ServerAddr = addr
	}
	// The bus owns accounts, tickets and links; the admin module owns
	// configuration (the JWT keypair, the directory settings). Both are asked
	// over HTTP with the same internal token, replacing the DSN that used to be
	// here.
	if busURL := os.Getenv("NANOAUTH_BUS_URL"); busURL != "" {
		cfg.BusURL = busURL
	}
	if adminURL := os.Getenv("NANOSEC_ADMIN_URL"); adminURL != "" {
		cfg.AdminURL = adminURL
	}
	if token := os.Getenv("NANOSEC_BUS_INTERNAL_TOKEN"); token != "" {
		cfg.BusToken = token
	}
	if pk := os.Getenv("NANOAUTH_JWT_KEY_ID"); pk != "" {
		cfg.JWT.KeyID = pk
	}
	if ttl := os.Getenv("NANOAUTH_TOKEN_TTL"); ttl != "" {
		if sec, err := strconv.Atoi(ttl); err == nil && sec > 0 {
			cfg.JWT.TokenTTL = sec
		}
	}
	if ttl := os.Getenv("NANOAUTH_REFRESH_TTL"); ttl != "" {
		if sec, err := strconv.Atoi(ttl); err == nil && sec > 0 {
			cfg.RefreshTokenTTL = sec
		}
	}
	if wechatAppID := os.Getenv("NANOAUTH_WECHAT_APP_ID"); wechatAppID != "" {
		cfg.WeChat.AppID = wechatAppID
	}
	if wechatSecret := os.Getenv("NANOAUTH_WECHAT_APP_SECRET"); wechatSecret != "" {
		cfg.WeChat.AppSecret = wechatSecret
	}

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create server: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		slog.Error("server stopped", "error", err)
	}
}
