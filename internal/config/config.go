package config

type AuthConfig struct {
	ServerAddr string `mapstructure:"server_addr"`
	// BusToken is the platform's shared internal token: the admin module, which
	// this service asks for its configuration and reports its audit trail to,
	// answers only requests that carry it.
	BusToken string `mapstructure:"bus_token"`
	// AdminURL is the admin module, which owns the configuration this service
	// reads and writes (the JWT keypair, the directory settings).
	AdminURL string `mapstructure:"admin_url"`
	// UIDir is the built front end this module contributes to the portal
	// (served at /plugins/auth/). Empty disables it: the module still works, the
	// portal then shows its own user page.
	UIDir           string `mapstructure:"ui_dir"`
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
		AdminURL:        "http://nanoadmin:8080",
		UIDir:           "/app/ui",
		RefreshTokenTTL: 604800, // refresh token lifetime in seconds (7d)
		JWT: JWTConfig{
			KeyID:    "2026-08",
			Issuer:   "nanoauth",
			TokenTTL: 43200, // access token lifetime in seconds (12h)
			KeyBits:  2048,
		},
	}
}
