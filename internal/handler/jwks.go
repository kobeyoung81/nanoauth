package handler

import (
	"net/http"

	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

type JWKSHandler struct {
	tokenSvc *token.TokenService
}

func NewJWKSHandler(tokenSvc *token.TokenService) *JWKSHandler {
	return &JWKSHandler{tokenSvc: tokenSvc}
}

func (h *JWKSHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.tokenSvc.JWKS()
	writeJSON(w, http.StatusOK, jwks)
}
