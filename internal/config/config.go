package config

type AuthConfig struct {
	ServerAddr string `mapstructure:"server_addr"`
	// The bus still answers the account surface this service has not taken over;
	// these two are its address and the platform's shared token.
	BusURL   string `mapstructure:"bus_url"`
	BusToken string `mapstructure:"bus_token"`
	// AdminURL is the admin module, which owns the configuration this service
	// reads and writes (the JWT keypair, the directory settings).
	AdminURL        string `mapstructure:"admin_url"`
	RefreshTokenTTL int    `mapstructure:"refresh_token_ttl"` // seconds, default 604800 (7d)
	JWT             JWTConfig
	WeChat          WeChatConfig `mapstructure:"wechat"`
}

// WeChatConfig holds WeChat Mini Program credentials for OAuth login.
type WeChatConfig struct {
	AppID     string `mapstructure:"app_id"`
	AppSecret string `mapstructure:"app_secret"`
}

type JWTConfig struct {
	KeyID    string `mapstructure:"key_id"`
	Issuer   string `mapstructure:"issuer"`
	TokenTTL int    `mapstructure:"token_ttl"` // seconds, default 3600
	KeyBits  int    `mapstructure:"key_bits"`  // RSA modulus size, default 2048
}

func DefaultConfig() AuthConfig {
	return AuthConfig{
		ServerAddr:      ":8081",
		BusURL:          "http://127.0.0.1:9000",
		AdminURL:        "http://nanoadmin:8080",
		RefreshTokenTTL: 604800, // refresh token lifetime in seconds (7d)
		JWT: JWTConfig{
			KeyID:    "2026-08",
			Issuer:   "nanoauth",
			TokenTTL: 43200, // access token lifetime in seconds (12h)
			KeyBits:  2048,
		},
	}
}
