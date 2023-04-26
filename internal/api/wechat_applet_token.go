package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/supabase/gotrue/internal/metering"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// Token is the endpoint for OAuth access token requests
func (a *API) WechatAppletToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "refresh_token":
		return a.WechatRefreshTokenGrant(ctx, w, r)
	default:
		return oauthError("unsupported_grant_type", "")
	}
}

// WechatRefreshTokenGrant implements the refresh_token grant type flow
func (a *API) WechatRefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	db := a.db.WithContext(ctx)
	config := a.config

	params := &RefreshTokenGrantParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read refresh token grant params: %v", err)
	}

	if params.RefreshToken == "" {
		return oauthError("invalid_request", "refresh_token required")
	}

	user, token, session, err := models.FindUserWithRefreshToken(db, params.RefreshToken)
	if err != nil {
		if models.IsNotFoundError(err) {
			return oauthError("invalid_grant", "Invalid Refresh Token: Refresh Token Not Found")
		}
		return internalServerError(err.Error())
	}

	if user.IsBanned() {
		return oauthError("invalid_grant", "Invalid Refresh Token: User Banned")
	}

	if session != nil {
		var notAfter time.Time

		if session.NotAfter != nil {
			notAfter = *session.NotAfter
		}

		if !notAfter.IsZero() && time.Now().UTC().After(notAfter) {
			return oauthError("invalid_grant", "Invalid Refresh Token: Session Expired")
		}
	}

	var newToken *models.RefreshToken
	if token.Revoked {
		a.clearCookieTokens(config, w)
		err = db.Transaction(func(tx *storage.Connection) error {
			validToken, terr := models.GetValidChildToken(tx, token)
			if terr != nil {
				if errors.Is(terr, models.RefreshTokenNotFoundError{}) {
					// revoked token has no descendants
					return nil
				}
				return terr
			}
			// check if token is the last previous revoked token
			if validToken.Parent == storage.NullString(token.Token) {
				refreshTokenReuseWindow := token.UpdatedAt.Add(time.Second * time.Duration(config.Security.RefreshTokenReuseInterval))
				if time.Now().Before(refreshTokenReuseWindow) {
					newToken = validToken
				}
			}
			return nil
		})
		if err != nil {
			return internalServerError("Error validating reuse interval").WithInternalError(err)
		}

		if newToken == nil {
			if config.Security.RefreshTokenRotationEnabled {
				// Revoke all tokens in token family
				err = db.Transaction(func(tx *storage.Connection) error {
					var terr error
					if terr = models.RevokeTokenFamily(tx, token); terr != nil {
						return terr
					}
					return nil
				})
				if err != nil {
					return internalServerError(err.Error())
				}
			}
			return oauthError("invalid_grant", "Invalid Refresh Token").WithInternalMessage("Possible abuse attempt: %v", r)
		}
	}

	var tokenString string
	var newTokenResponse *AccessTokenResponse

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.TokenRefreshedAction, "", nil); terr != nil {
			return terr
		}

		if newToken == nil {
			newToken, terr = models.GrantRefreshTokenSwap(r, tx, user, token)
			if terr != nil {
				return internalServerError(terr.Error())
			}
		}
		tokenString, terr = generateAccessToken(tx, user, newToken.SessionId, time.Second*time.Duration(config.JWT.Exp), config.JWT.Secret)

		if terr != nil {
			return internalServerError("error generating jwt token").WithInternalError(terr)
		}

		newTokenResponse = &AccessTokenResponse{
			Token:        tokenString,
			TokenType:    "bearer",
			ExpiresIn:    config.JWT.Exp,
			RefreshToken: newToken.Token,
			User:         user,
		}
		if terr = a.setCookieTokens(config, newTokenResponse, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}

		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("token", user.ID)
	return sendJSON(w, http.StatusOK, newTokenResponse)
}
