package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
	"gitee.com/kobeyoung81/nanoauth/internal/config"
	"gitee.com/kobeyoung81/nanoauth/internal/directory"
	"gitee.com/kobeyoung81/nanoauth/internal/handler"
	"gitee.com/kobeyoung81/nanoauth/internal/middleware"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

// Server is nanoauth.
//
// The identity collections are this service's — accounts, channel links, OAuth
// links, refresh tickets and a user's starred paths — and `accounts` is their
// store. It may be nil in a deployment without a database URI, in which case the
// internal surface reports itself unavailable rather than answering empty. The
// configuration, which this service reads and writes, is the admin module's and
// arrives over HTTP.
type Server struct {
	cfg      config.AuthConfig
	bus      *bus.Client
	accounts *store.Store
	httpSrv  *http.Server
}

// New builds the service. accounts may be nil (no database configured).
func New(cfg config.AuthConfig, accounts *store.Store) (*Server, error) {
	if cfg.BusURL == "" {
		return nil, fmt.Errorf("bus URL is required")
	}
	return &Server{cfg: cfg, bus: bus.New(cfg.BusURL, cfg.BusToken), accounts: accounts}, nil
}

// loadJWTKeyWithRetry tolerates an admin module that is still starting: the key
// is a hard dependency (nothing can be signed without it), so it retries for
// about 30 seconds and then fails the process rather than serving tokens signed
// with a key nobody else has.
func loadJWTKeyWithRetry(ctx context.Context, keyStore *store.KeyStore, bits int) (string, string, error) {
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	var lastErr error
	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", "", ctx.Err()
			case <-time.After(delays[attempt-1]):
			}
		}
		privatePEM, publicPEM, err := keyStore.GetOrCreateJWTKey(ctx, bits)
		if err == nil {
			if attempt > 0 {
				slog.Info("admin config became reachable", "attempts", attempt+1)
			}
			return privatePEM, publicPEM, nil
		}
		lastErr = err
		slog.Warn("jwt key not readable yet", "attempt", attempt+1, "error", err)
	}
	return "", "", lastErr
}

func (s *Server) Start(ctx context.Context) error {
	// The RSA JWT keypair lives in the shared configuration (generated on first
	// boot), so no key files or secrets need to be mounted and every replica signs
	// with the same key.
	// Configuration lives in the admin module now; the bus serves messages only.
	admin := bus.NewFor("admin", s.cfg.AdminURL, s.cfg.BusToken)
	keyStore := store.NewKeyStore(admin)
	privatePEM, publicPEM, err := loadJWTKeyWithRetry(ctx, keyStore, s.cfg.JWT.KeyBits)
	if err != nil {
		return fmt.Errorf("load jwt key: %w", err)
	}

	tokenSvc, err := token.NewTokenService(
		s.cfg.JWT.KeyID,
		s.cfg.JWT.Issuer,
		s.cfg.JWT.TokenTTL,
		privatePEM,
		publicPEM,
	)
	if err != nil {
		return err
	}

	userStore := store.NewUserStore(s.bus).WithAccounts(s.accounts)
	tokenStore := store.NewTokenStore(s.bus).WithAccounts(s.accounts)
	tokenStore.SetTTL(time.Duration(s.cfg.RefreshTokenTTL) * time.Second)

	// The directory login reads its settings from the shared config store, so an
	// edit in the portal takes effect without restarting nanoauth.
	directoryLoader := directory.NewLoader(admin)
	authHandler := handler.NewAuthHandler(tokenSvc, userStore, tokenStore).
		WithDirectory(directory.NewClient(), directoryLoader)
	directoryHandler := handler.NewDirectoryHandler(directory.NewClient(), directoryLoader, userStore)
	oauthHandler := handler.NewOAuthHandler(tokenSvc, userStore, s.cfg.WeChat.AppID, s.cfg.WeChat.AppSecret)
	jwksHandler := handler.NewJWKSHandler(tokenSvc)

	// The console routes need a verified token *and* a management role: the
	// portal forwards the caller's token, so a direct call to this service is
	// held to the same rule as a call through the portal.
	requireAuth := middleware.AuthMiddleware(tokenSvc)
	managementOnly := middleware.RequireRoles(middleware.RoleAdmin, middleware.RoleOperator)
	directoryAdmin := func(next http.HandlerFunc) http.Handler {
		return requireAuth(managementOnly(next))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/v1/register", authHandler.HandleRegister)
	mux.HandleFunc("POST /auth/v1/token", authHandler.HandleToken)
	mux.HandleFunc("POST /auth/v1/token/refresh", authHandler.HandleRefresh)
	mux.HandleFunc("POST /auth/v1/logout", authHandler.HandleLogout)
	mux.HandleFunc("GET /auth/v1/userinfo", authHandler.HandleUserinfo)
	mux.HandleFunc("POST /auth/v1/oauth/wechat", oauthHandler.HandleWeChatOAuth)
	mux.HandleFunc("GET /auth/v1/.well-known/jwks", jwksHandler.HandleJWKS)

	// The internal account surface: the bus fronts these for the console and the
	// runtime, and forwards them here.
	mux.Handle("GET /internal/v1/users/{userID}/git-shortcuts", s.internalGuard(s.internalListGitShortcuts))
	mux.Handle("POST /internal/v1/users/{userID}/git-shortcuts", s.internalGuard(s.internalSaveGitShortcut))
	mux.Handle("DELETE /internal/v1/users/{userID}/git-shortcuts/{id}", s.internalGuard(s.internalDeleteGitShortcut))
	mux.Handle("GET /internal/v1/users/{userID}/secrets/{kind}/{ref}", s.internalGuard(s.internalListSecrets))
	mux.Handle("PUT /internal/v1/users/{userID}/secrets/{kind}/{ref}", s.internalGuard(s.internalSetSecret))
	mux.Handle("DELETE /internal/v1/users/{userID}/secrets/{kind}/{ref}", s.internalGuard(s.internalDeleteSecret))
	mux.Handle("GET /internal/v1/users/{userID}/oauth-links", s.internalGuard(s.internalListOAuthLinks))
	mux.Handle("POST /internal/v1/users/{userID}/oauth-links/{provider}", s.internalGuard(s.internalLinkOAuth))
	mux.Handle("DELETE /internal/v1/users/{userID}/oauth-links/{provider}", s.internalGuard(s.internalUnlinkOAuth))
	mux.Handle("GET /internal/v1/oauth-links", s.internalGuard(s.internalListOAuthLinksByProvider))

	// Directory login console (read-only; the settings themselves live in
	// service_config_items and are edited through the bus config API).
	mux.Handle("GET /auth/v1/directory/effective", directoryAdmin(directoryHandler.HandleEffective))
	mux.Handle("POST /auth/v1/directory/validate", directoryAdmin(directoryHandler.HandleValidate))
	mux.Handle("POST /auth/v1/directory/test", directoryAdmin(directoryHandler.HandleTest))
	mux.Handle("POST /auth/v1/directory/browse", directoryAdmin(directoryHandler.HandleBrowse))
	mux.Handle("POST /auth/v1/directory/analyze", directoryAdmin(directoryHandler.HandleAnalyze))
	mux.Handle("POST /auth/v1/directory/search", directoryAdmin(directoryHandler.HandleSearch))
	mux.Handle("POST /auth/v1/directory/check", directoryAdmin(directoryHandler.HandleCheck))

	s.httpSrv = &http.Server{
		Addr:    s.cfg.ServerAddr,
		Handler: withCORS(mux),
	}

	slog.Info("nanoauth starting", "addr", s.cfg.ServerAddr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpSrv.Shutdown(shutdownCtx)
		// Nothing to close: the bus holds the connections.
	}()

	return s.httpSrv.ListenAndServe()
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
