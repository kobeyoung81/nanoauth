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

// Server is nanoauth. It has no database of its own: the bus owns every
// collection this service reads — accounts, credentials, directory links,
// refresh tickets and the shared configuration — so all of it arrives through the
// bus's internal API.
type Server struct {
	cfg     config.AuthConfig
	bus     *bus.Client
	httpSrv *http.Server
}

func New(cfg config.AuthConfig) (*Server, error) {
	if cfg.BusURL == "" {
		return nil, fmt.Errorf("bus URL is required")
	}
	return &Server{cfg: cfg, bus: bus.New(cfg.BusURL, cfg.BusToken)}, nil
}

func (s *Server) Start(ctx context.Context) error {
	// The RSA JWT keypair lives in the shared configuration (generated on first
	// boot), so no key files or secrets need to be mounted and every replica signs
	// with the same key.
	keyStore := store.NewKeyStore(s.bus)
	privatePEM, publicPEM, err := keyStore.GetOrCreateJWTKey(ctx, s.cfg.JWT.KeyBits)
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

	userStore := store.NewUserStore(s.bus)
	tokenStore := store.NewTokenStore(s.bus)
	tokenStore.SetTTL(time.Duration(s.cfg.RefreshTokenTTL) * time.Second)

	// The directory login reads its settings from the shared config store, so an
	// edit in the portal takes effect without restarting nanoauth.
	directoryLoader := directory.NewLoader(s.bus)
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
