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

type PhoneOneClickSignupParams struct {
	Email    string                 `json:"email"`
	Phone    string                 `json:"phone"`
	Password string                 `json:"password"`
	Data     map[string]interface{} `json:"data"`
	Provider string                 `json:"-"`
	Aud      string                 `json:"-"`
	Channel  string                 `json:"channel"`

	//uniCloud云函数一键登录所需参数
	AccessToken string `json:"access_token"`
	Openid      string `json:"openid`
}

const PHONE_ONE_CLINET_PROVIDER_NAME = "phoneOneClick"

func (a *API) PhoneOneClickSignup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}

	params := &PhoneOneClickSignupParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read Signup params: %v", err)
	}

	if params.AccessToken == "" {
		return unprocessableEntityError("Signup requires access_token")
	}

	if params.Openid == "" {
		return unprocessableEntityError("Signup requires openid")
	}

	params.Provider = PHONE_ONE_CLINET_PROVIDER_NAME

	var phone string
	phone, err = UniCloudGetPhone(config, params.AccessToken, params.Openid)
	if err != nil {
		return err
	}

	params.Phone = phone

	logrus.Info("PhoneOneClickSignup params: ", params)

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
			logrus.Info("PhoneOneClickSignup user exist, start sign in")

			if params.Provider == PHONE_ONE_CLINET_PROVIDER_NAME && user.IsConfirmed() {
				return UserExistsError
			}

			// do not update the user because we can't be sure of their claimed identity
		} else {
			logrus.Info("PhoneOneClickSignup user does not exist, start sign up")

			user, terr = a.phoneOneClickSignupNewUser(ctx, tx, params, false /* <- isSSOUser */)
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

		logrus.Info("PhoneOneClickSignup user info: ", *user)

		if params.Provider == PHONE_ONE_CLINET_PROVIDER_NAME && !user.IsPhoneConfirmed() {
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
			sanitizedUser, err := phoneOneClickSanitizeUser(user, params)
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

// 请求UniCloud获取手机号
func UniCloudGetPhone(ext *conf.GlobalConfiguration, accessToken string, openid string) (string, error) {
	logrus.Info("UniCloudGetPhone accessToken: ", accessToken, ",openid: ", openid)

	var getPhoneUrl = ext.External.UnicloudPhoneOneClickFunctionUrl

	resp, err := http.Post(getPhoneUrl, "application/json", strings.NewReader("{\"access_token\":\""+accessToken+"\", \"openid\":\""+openid+"\"}"))
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)

	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		logrus.Info("UniCloudGetPhone, Response: %v", resp)

		return "", badRequestError("UniCloud API return error, StatusCode: %d", code)
	}

	logrus.Info("UniCloudGetPhone response body: " + string(body))

	var uniCloudGetPhoneResult UniCloudGetPhoneResult
	if err = json.Unmarshal(body, &uniCloudGetPhoneResult); err != nil {
		return "", err
	}

	if !uniCloudGetPhoneResult.Res.Success {
		logrus.Info("UniCloudGetPhone request get phone error, Response Result: ", string(body))

		return "", badRequestError("UniCloudGetPhone API return error, code: %s, message: %s", uniCloudGetPhoneResult.Error.Code, uniCloudGetPhoneResult.Error.Message)
	}

	var phone = uniCloudGetPhoneResult.Res.PhoneNumber

	return phone, nil
}

/*
*

	返回值样例-成功
	{
	"res": {
	"code": 0,
	"success": true,
	"phoneNumber": "xxxxxxxxxxx"
	}
	}

	返回值样例-失败
	{
	"success": false,
	"error": {
	"code": "FunctionBizError",
	"message": "5000:获取手机号码失败：获取号码失败"
	}
	}
*/
type UniCloudGetPhoneResult struct {
	Res Res `json:"res"`

	Success bool `json:"success"`

	Error Error `json:"error"`
}

type Res struct {
	//返回编码
	Code int `json:"code"`
	//是否成功
	Success bool `json:"success"`
	//手机号
	PhoneNumber string `json:"phoneNumber"`
}

type Error struct {
	Code string `json:"code"`

	Message string `json:"message"`
}

// sanitizeUser removes all user sensitive information from the user object
// Should be used whenever we want to prevent information about whether a user is registered or not from leaking
func phoneOneClickSanitizeUser(u *models.User, params *PhoneOneClickSignupParams) (*models.User, error) {
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

func (a *API) phoneOneClickSignupNewUser(ctx context.Context, conn *storage.Connection, params *PhoneOneClickSignupParams, isSSOUser bool) (*models.User, error) {
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
