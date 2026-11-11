package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"gitee.com/kobeyoung81/nanoauth/internal/config"
	"gitee.com/kobeyoung81/nanoauth/internal/server"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/migrations"
)

// openAccounts connects to the platform database and applies this service's
// manifests.
//
// The collections are already in the platform database, created by the module
// that used to hold the only connection, so applying the manifests is a no-op
// there and a fresh installation gets its indexes. An unconfigured URI is
// reported rather than fatal: the endpoints that need accounts then answer
// "not configured", which is a clearer failure than refusing to start.
func openAccounts() *store.Store {
	uri := accountsMongoURI()
	if uri == "" {
		slog.Warn("accounts database is not configured; the internal account endpoints will refuse",
			"hint", "set NANOAUTH_MONGO_URI or NANOSEC_BUS_DATABASE_URI")
		return nil
	}
	st, err := store.Open(uri)
	if err != nil {
		slog.Error("open accounts database", "error", err)
		return nil
	}

	manifests, err := migrations.Load()
	if err != nil {
		slog.Error("load account manifests", "error", err)
		_ = st.Close()
		return nil
	}
	ran, err := st.Migrate(manifests)
	if err != nil {
		slog.Error("apply account manifests", "error", err)
		_ = st.Close()
		return nil
	}
	slog.Info("account manifests applied", "count", len(ran))
	return st
}

// accountsMongoURI names the platform database, falling back to the bus's
// variable so a deployment only has to fill in one URI. The collection prefix is
// what separates modules, not the credentials.
func accountsMongoURI() string {
	if v := strings.TrimSpace(os.Getenv("NANOAUTH_MONGO_URI")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("NANOSEC_BUS_DATABASE_URI"))
}

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

	// Accounts, channel links, OAuth links and refresh tickets are identity's, so
	// the database connection is this service's. The manifests describe the
	// indexes those collections already have; applying them to a database where
	// another module created them is a no-op.
	accounts := openAccounts()
	if accounts != nil {
		defer func() { _ = accounts.Close() }()
	}

	srv, err := server.New(cfg, accounts)
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
