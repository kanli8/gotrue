package api

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/supabase/gotrue/internal/api/provider"
	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/metering"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

type WeChatSignupParams struct {
	Email    string                 `json:"email"`
	Phone    string                 `json:"phone"`
	Password string                 `json:"password"`
	Data     map[string]interface{} `json:"data"`
	Provider string                 `json:"-"`
	Aud      string                 `json:"-"`
	Channel  string                 `json:"channel"`
	//The code needed to get the phone number
	Code string `json:"code"`
}

const PROVIDER_NAME = "wechatApplet"

func (a *API) WeChatAppletSignup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}

	params := &WeChatSignupParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read Signup params: %v", err)
	}

	if params.Code == "" {
		return unprocessableEntityError("Signup requires code")
	}

	params.Provider = PROVIDER_NAME

	var phone string
	phone, err = WeChatAppletGetPhone(config, params.Code)
	if err != nil {
		return err
	}

	params.Phone = phone

	if params.Data == nil {
		params.Data = make(map[string]interface{})
	}

	// For backwards compatibility, we default to SMS if params Channel is not specified
	if params.Phone != "" && params.Channel == "" {
		params.Channel = sms_provider.SMSProvider
	}

	var user *models.User
	var grantParams models.GrantParams
	params.Aud = a.requestAud(ctx, r)

	params.Phone, err = validatePhone(params.Phone)
	if err != nil {
		return err
	}
	user, err = models.FindUserByPhoneAndAudience(db, params.Phone, params.Aud)

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user != nil {
			logrus.Info("WeChatAppletSignup user exist, start sign in")

			if params.Provider == PROVIDER_NAME && user.IsConfirmed() {
				return UserExistsError
			}

			// do not update the user because we can't be sure of their claimed identity
		} else {
			logrus.Info("WeChatAppletSignup user does not exist, start sign up")

			user, terr = a.wechatSignupNewUser(ctx, tx, params, false /* <- isSSOUser */)
			if terr != nil {
				return terr
			}
			identity, terr := a.createNewIdentity(tx, user, params.Provider, structs.Map(provider.Claims{
				Subject: user.ID.String(),
				Email:   user.GetEmail(),
			}))
			if terr != nil {
				return terr
			}
			user.Identities = []models.Identity{*identity}
		}

		logrus.Info("WeChatAppletSignup user info: ", *user)

		if params.Provider == PROVIDER_NAME && !user.IsPhoneConfirmed() {
			if terr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
				"provider": params.Provider,
				"channel":  params.Channel,
			}); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
				return terr
			}
			if terr = user.ConfirmPhone(tx); terr != nil {
				return internalServerError("Database error updating user").WithInternalError(terr)
			}
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every minute")
		}
		if errors.Is(err, UserExistsError) {
			err = db.Transaction(func(tx *storage.Connection) error {
				if terr := models.NewAuditLogEntry(r, tx, user, models.UserRepeatedSignUpAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); terr != nil {
					return terr
				}
				return nil
			})
			if err != nil {
				return err
			}
			if config.Mailer.Autoconfirm || config.Sms.Autoconfirm {
				return badRequestError("User already registered")
			}
			sanitizedUser, err := weChatSanitizeUser(user, params)
			if err != nil {
				return err
			}
			return sendJSON(w, http.StatusOK, sanitizedUser)
		}
		return err
	}

	// handles case where Mailer.Autoconfirm is true or Phone.Autoconfirm is true
	if user.IsConfirmed() || user.IsPhoneConfirmed() {
		var token *AccessTokenResponse
		err = db.Transaction(func(tx *storage.Connection) error {
			var terr error
			if terr = models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
				"provider": params.Provider,
			}); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, config); terr != nil {
				return terr
			}
			token, terr = a.issueRefreshToken(ctx, tx, user, models.PasswordGrant, grantParams)

			if terr != nil {
				return terr
			}

			if terr = a.setCookieTokens(config, token, false, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
			return nil
		})
		if err != nil {
			return err
		}
		metering.RecordLogin("password", user.ID)
		return sendJSON(w, http.StatusOK, token)
	}

	return sendJSON(w, http.StatusOK, user)
}

// get wechat phone
func WeChatAppletGetPhone(ext *conf.GlobalConfiguration, code string) (string, error) {
	var appid = ext.External.WechatAppletAppId
	var appSecret = ext.External.WechatAppletAppSecret

	var accessToken, getWeChatTokenError = getWeChatToken(appid, appSecret)
	if getWeChatTokenError != nil {
		return "", getWeChatTokenError
	}

	var phone, getWeChatPhoneErr = getWeChatPhone(accessToken, code)
	if getWeChatPhoneErr != nil {
		return "", getWeChatPhoneErr
	}

	return phone, nil
}

func getWeChatToken(appid string, appSecret string) (string, error) {
	var getWeChatToken = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + appid + "&secret=" + appSecret

	resp, err := http.Get(getWeChatToken)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		logrus.Info("getWeChatToken Response: %v", resp)

		return "", badRequestError("WeChat API return error, StatusCode: %d", code)
	}

	logrus.Info("getWeChatToken response body: " + string(body))

	var wechatToken WeChatToken
	if err = json.Unmarshal(body, &wechatToken); err != nil {
		return "", err
	}

	if wechatToken.Errcode != 0 {
		logrus.Info("getWeChatToken Response Result: ", string(body))

		return "", badRequestError("WeChat API return error, code: %d, msg: %s", wechatToken.Errcode, wechatToken.Errmsg)
	}

	accessToken := wechatToken.AccessToken

	return accessToken, nil
}

type WeChatToken struct {
	AccessToken string         `json:"access_token"`
	ExpiresIn   expirationTime `json:"expires_in"`

	Errcode int    `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

type expirationTime int32

func getWeChatPhone(accessToken string, code string) (string, error) {
	logrus.Info("getWeChatPhone accessToken: ", accessToken, ", code: ", code)

	var getWeChatPhone = "https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=" + accessToken

	resp, err := http.Post(getWeChatPhone, "application/json", strings.NewReader("{\"code\":\""+code+"\"}"))
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		logrus.Info("getWeChatPhone, Response: %v", resp)

		return "", badRequestError("WeChat API return error, StatusCode: %d", code)
	}

	logrus.Info("getWeChatPhone response body: " + string(body))

	var weChatPhoneResult WeChatPhoneResult
	if err = json.Unmarshal(body, &weChatPhoneResult); err != nil {
		return "", err
	}

	if weChatPhoneResult.Errcode != 0 {
		logrus.Info("getWeChatPhone request error, Response Result: ", string(body))

		return "", badRequestError("WeChat API return error, code: %d, msg: %s", weChatPhoneResult.Errcode, weChatPhoneResult.Errmsg)
	}

	var phone = weChatPhoneResult.PhoneInfo.PurePhoneNumber

	return phone, nil
}

type WeChatPhoneResult struct {
	//error code
	Errcode int `json:"errcode"`
	//error message
	Errmsg string `json:"errmsg"`
	//user phone info
	PhoneInfo PhoneInfo `json:"phone_info"`
}

type Watermark struct {
	//The timestamp of the user's operation to obtain the phone number
	Timestamp int `json:"timestamp"`
	//wechat applet appid
	Appid string `json:"appid"`
}

type PhoneInfo struct {
	//The mobile phone number attached to the user (foreign mobile phone numbers will have area code)
	PhoneNumber string `json:"phoneNumber"`
	//A phone number without an area code
	PurePhoneNumber string `json:"purePhoneNumber"`
	//area code
	CountryCode string    `json:"countryCode"`
	Watermark   Watermark `json:"watermark"`
}

// sanitizeUser removes all user sensitive information from the user object
// Should be used whenever we want to prevent information about whether a user is registered or not from leaking
func weChatSanitizeUser(u *models.User, params *WeChatSignupParams) (*models.User, error) {
	var err error
	now := time.Now()

	u.ID, err = uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	u.CreatedAt, u.UpdatedAt, u.ConfirmationSentAt = now, now, &now
	u.LastSignInAt, u.ConfirmedAt, u.EmailConfirmedAt, u.PhoneConfirmedAt = nil, nil, nil, nil
	u.Identities = make([]models.Identity, 0)
	u.UserMetaData = params.Data
	u.Aud = params.Aud

	// sanitize app_metadata
	u.AppMetaData = map[string]interface{}{
		"provider":  params.Provider,
		"providers": []string{params.Provider},
	}

	u.Email = ""

	return u, nil
}

func (a *API) wechatSignupNewUser(ctx context.Context, conn *storage.Connection, params *WeChatSignupParams, isSSOUser bool) (*models.User, error) {
	config := a.config

	var user *models.User
	var err error

	user, err = models.NewUser(params.Phone, "", "", params.Aud, params.Data)

	user.IsSSOUser = isSSOUser

	if err != nil {
		return nil, internalServerError("Database error creating user").WithInternalError(err)
	}
	if user.AppMetaData == nil {
		user.AppMetaData = make(map[string]interface{})
	}

	user.Identities = make([]models.Identity, 0)

	// TODO: Deprecate "provider" field
	user.AppMetaData["provider"] = params.Provider

	user.AppMetaData["providers"] = []string{params.Provider}
	if params.Password == "" {
		user.EncryptedPassword = ""
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = tx.Create(user); terr != nil {
			return internalServerError("Database error saving new user").WithInternalError(terr)
		}
		if terr = user.SetRole(tx, config.JWT.DefaultGroupName); terr != nil {
			return internalServerError("Database error updating user").WithInternalError(terr)
		}
		if terr = triggerEventHooks(ctx, tx, ValidateEvent, user, config); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// sometimes there may be triggers in the database that will modify the
	// user data as it is being inserted. thus we load the user object
	// again to fetch those changes.
	err = conn.Eager().Load(user)
	if err != nil {
		return nil, internalServerError("Database error loading user after sign-up").WithInternalError(err)
	}

	return user, nil
}
