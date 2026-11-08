package config

type AuthConfig struct {
	ServerAddr string `mapstructure:"server_addr"`
	// The bus owns every collection this service reads; these two are the whole
	// storage configuration. There is no DSN to point anywhere.
	BusURL          string `mapstructure:"bus_url"`
	BusToken        string `mapstructure:"bus_token"`
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
		RefreshTokenTTL: 604800, // refresh token lifetime in seconds (7d)
		JWT: JWTConfig{
			KeyID:    "2026-08",
			Issuer:   "nanoauth",
			TokenTTL: 43200, // access token lifetime in seconds (12h)
			KeyBits:  2048,
		},
	}
}
