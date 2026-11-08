package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

const wechatCode2SessionURL = "https://api.weixin.qq.com/sns/jscode2session"

// oauthHandler handles WeChat OAuth login for the mini program.
type oauthHandler struct {
	tokenSvc  *token.TokenService
	userStore *store.UserStore
	appID     string
	appSecret string
	client    *http.Client
}

// NewOAuthHandler creates a handler for WeChat OAuth flows.
func NewOAuthHandler(tokenSvc *token.TokenService, userStore *store.UserStore, appID, appSecret string) *oauthHandler {
	return &oauthHandler{
		tokenSvc:  tokenSvc,
		userStore: userStore,
		appID:     appID,
		appSecret: appSecret,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

type oauthLoginRequest struct {
	Code string `json:"code"`
}

type wechatSession struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid"`
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
}

// HandleWeChatOAuth exchanges a WeChat login code for a platform JWT.
func (h *oauthHandler) HandleWeChatOAuth(w http.ResponseWriter, r *http.Request) {
	if h.appID == "" || h.appSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "wechat oauth not configured")
		return
	}

	var req oauthLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	session, err := h.code2session(req.Code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "wechat code exchange failed: "+err.Error())
		return
	}
	if session.ErrCode != 0 {
		writeError(w, http.StatusUnauthorized, "wechat error: "+session.ErrMsg)
		return
	}

	const provider = "wechat"
	user, err := h.userStore.GetByOAuthProvider(r.Context(), provider, session.OpenID)
	if err != nil {
		slog.Error("lookup wechat user", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	displayName := "WeChat User"
	if user == nil {
		userID, err := h.userStore.CreateWithOAuth(r.Context(), provider, session.OpenID, displayName)
		if err != nil {
			slog.Error("create wechat user", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		user = &store.UserRecord{ID: userID, Role: "user", Tier: "free", Status: "active", DisplayName: displayName}
	}

	accessToken, expiresAt, err := h.tokenSvc.GenerateAccessToken(user.ID, user.DisplayName, user.Role, user.Tier)
	if err != nil {
		slog.Error("generate token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(expiresAt.Sub(time.Now()).Seconds()),
		"user_id":      user.ID,
		"role":         user.Role,
		"tier":         user.Tier,
		"display_name": user.DisplayName,
	})
}

func (h *oauthHandler) code2session(code string) (*wechatSession, error) {
	params := url.Values{}
	params.Set("appid", h.appID)
	params.Set("secret", h.appSecret)
	params.Set("js_code", code)
	params.Set("grant_type", "authorization_code")

	resp, err := h.client.Get(wechatCode2SessionURL + "?" + params.Encode())
	if err != nil {
		return nil, fmt.Errorf("wechat code2session: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read code2session: %w", err)
	}

	var session wechatSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("decode code2session: %w", err)
	}
	return &session, nil
}
