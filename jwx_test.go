package jwx_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	jwx "github.com/lestrrat-go/echo-middleware-jwx"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWXRace(t *testing.T) {
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}
	initialToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	raceToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlJhY2UgQ29uZGl0aW9uIiwiYWRtaW4iOmZhbHNlfQ.Xzkx9mcgGqYMTkuxSCbJ67lsDyk5J2aB7hu65cEE-Ss"
	validKey := []byte("secret")
	key, err := jwk.FromRaw(validKey)
	if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
		return
	}

	h := jwx.WithConfig(jwx.Config{
		Key: key,
	})(handler)

	makeReq := func(token string) echo.Context {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		req.Header.Set(echo.HeaderAuthorization, jwx.DefaultConfig.AuthScheme+" "+token)
		c := e.NewContext(req, res)
		if !assert.NoError(t, h(c)) {
			panic("error")
		}
		return c
	}

	c := makeReq(initialToken)
	user := c.Get("user").(jwt.Token)

	{
		v, ok := user.Get("name")
		if !assert.True(t, ok, "'name' field should exist") {
			return
		}
		if !assert.Equal(t, v, "John Doe", "'name' field should match") {
			return
		}
	}

	makeReq(raceToken)
	user = c.Get("user").(jwt.Token)

	// Initial context should still be "John Doe", not "Race Condition"
	{
		v, ok := user.Get("name")
		if !assert.True(t, ok, "'name' field should exist") {
			return
		}
		if !assert.Equal(t, v, "John Doe", "'name' field should match") {
			return
		}
	}
	{
		v, ok := user.Get("admin")
		if !assert.True(t, ok, "'adming' field should exist") {
			return
		}
		if !assert.Equal(t, v, true, "'admin' field should match") {
			return
		}
	}
}

func TestJWX(t *testing.T) {
	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	validRawKey := []byte("secret")
	invalidRawKey := []byte("invalid-key")
	validKey, err := jwk.FromRaw(validRawKey)
	if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
		return
	}
	invalidKey, err := jwk.FromRaw(invalidRawKey)
	if !assert.NoError(t, err, `jwk.FromRaw should succeed`) {
		return
	}
	validAuth := jwx.DefaultConfig.AuthScheme + " " + token

	for _, tc := range []struct {
		expPanic   bool
		expErrCode int // 0 for Success
		config     jwx.Config
		reqURL     string // "/" if empty
		hdrAuth    string
		hdrCookie  string // test.Request doesn't provide SetCookie(); use name=val
		formValues map[string]string
		info       string
	}{
		{
			expErrCode: http.StatusBadRequest,
			config: jwx.Config{
				Key:                validKey,
				SignatureAlgorithm: "RS256",
			},
			info: "Unexpected signing method",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    validAuth,
			config:     jwx.Config{Key: invalidKey},
			info:       "Invalid key",
		},
		{
			hdrAuth: validAuth,
			config:  jwx.Config{Key: validKey},
			info:    "Valid JWT",
		},
		{
			hdrAuth: "Token" + " " + token,
			config:  jwx.Config{AuthScheme: "Token", Key: validKey},
			info:    "Valid JWT with custom AuthScheme",
		},
		{
			hdrAuth: validAuth,
			config: jwx.Config{
				Key: validKey,
			},
			info: "Valid JWT with custom claims",
		},
		{
			hdrAuth:    "invalid-auth",
			expErrCode: http.StatusBadRequest,
			config:     jwx.Config{Key: validKey},
			info:       "Invalid Authorization header",
		},
		{
			config:     jwx.Config{Key: validKey},
			expErrCode: http.StatusBadRequest,
			info:       "Empty header auth field",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "query:jwt",
			},
			reqURL: "/?a=b&jwt=" + token,
			info:   "Valid query method",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "query:jwt",
			},
			reqURL:     "/?a=b&jwtxyz=" + token,
			expErrCode: http.StatusBadRequest,
			info:       "Invalid query param name",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "query:jwt",
			},
			reqURL:     "/?a=b&jwt=invalid-token",
			expErrCode: http.StatusUnauthorized,
			info:       "Invalid query param value",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "query:jwt",
			},
			reqURL:     "/?a=b",
			expErrCode: http.StatusBadRequest,
			info:       "Empty query",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "param:jwt",
			},
			reqURL: "/" + token,
			info:   "Valid param method",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "cookie:jwt",
			},
			hdrCookie: "jwt=" + token,
			info:      "Valid cookie method",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "query:jwt,cookie:jwt",
			},
			hdrCookie: "jwt=" + token,
			info:      "Multiple jwt lookuop",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "cookie:jwt",
			},
			expErrCode: http.StatusUnauthorized,
			hdrCookie:  "jwt=invalid",
			info:       "Invalid token with cookie method",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "cookie:jwt",
			},
			expErrCode: http.StatusBadRequest,
			info:       "Empty cookie",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "form:jwt",
			},
			formValues: map[string]string{"jwt": token},
			info:       "Valid form method",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "form:jwt",
			},
			expErrCode: http.StatusUnauthorized,
			formValues: map[string]string{"jwt": "invalid"},
			info:       "Invalid token with form method",
		},
		{
			config: jwx.Config{
				Key:         validKey,
				TokenLookup: "form:jwt",
			},
			expErrCode: http.StatusBadRequest,
			info:       "Empty form field",
		},
		{
			hdrAuth: validAuth,
			config: jwx.Config{
				KeyFunc: func(echo.Context) (interface{}, error) {
					return validKey, nil
				},
			},
			info: "Valid JWT with a valid key using a user-defined KeyFunc",
		},
		{
			hdrAuth: validAuth,
			config: jwx.Config{
				KeyFunc: func(echo.Context) (interface{}, error) {
					return invalidKey, nil
				},
			},
			expErrCode: http.StatusUnauthorized,
			info:       "Valid JWT with an invalid key using a user-defined KeyFunc",
		},
		{
			hdrAuth: validAuth,
			config: jwx.Config{
				KeyFunc: func(echo.Context) (interface{}, error) {
					return nil, errors.New("faulty KeyFunc")
				},
			},
			expErrCode: http.StatusUnauthorized,
			info:       "Token verification does not pass using a user-defined KeyFunc",
		},
	} {
		if tc.reqURL == "" {
			tc.reqURL = "/"
		}

		var req *http.Request
		if len(tc.formValues) > 0 {
			form := url.Values{}
			for k, v := range tc.formValues {
				form.Set(k, v)
			}
			req = httptest.NewRequest(http.MethodPost, tc.reqURL, strings.NewReader(form.Encode()))
			req.Header.Set(echo.HeaderContentType, "application/x-www-form-urlencoded")
			_ = req.ParseForm()
		} else {
			req = httptest.NewRequest(http.MethodGet, tc.reqURL, nil)
		}
		res := httptest.NewRecorder()
		req.Header.Set(echo.HeaderAuthorization, tc.hdrAuth)
		req.Header.Set(echo.HeaderCookie, tc.hdrCookie)
		c := e.NewContext(req, res)

		if tc.reqURL == "/"+token {
			c.SetParamNames("jwt")
			c.SetParamValues(token)
		}

		if tc.expPanic {
			assert.Panics(t, func() {
				jwx.WithConfig(tc.config)
			}, tc.info)
			continue
		}

		if tc.expErrCode != 0 {
			h := jwx.WithConfig(tc.config)(handler)
			he := h(c).(*echo.HTTPError)
			assert.Equal(t, tc.expErrCode, he.Code, tc.info)
			continue
		}

		h := jwx.WithConfig(tc.config)(handler)
		if assert.NoError(t, h(c), tc.info) {
			user := c.Get("user").(jwt.Token)
			{
				v, ok := user.Get("name")
				if !assert.True(t, ok, `'name' field should exist`) {
					return
				}
				if !assert.Equal(t, v, "John Doe", tc.info) {
					return
				}
			}

			{
				v, ok := user.Get("admin")
				if ok {
					if !assert.Equal(t, v, true, tc.info) {
						return
					}
				}
			}
		}
	}
}

func TestJWXwithKID(t *testing.T) {
	test := assert.New(t)

	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}
	firstToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImZpcnN0T25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.w5VGpHOe0jlNgf7jMVLHzIYH_XULmpUlreJnilwSkWk"
	secondToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InNlY29uZE9uZSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.sdghDYQ85jdh0hgQ6bKbMguLI_NSPYWjkhVJkee-yZM"
	wrongToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InNlY29uZE9uZSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.RyhLybtVLpoewF6nz9YN79oXo32kAtgUxp8FNwTkb90"
	staticToken := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.1_-XFYUPpJfgsaGwYhgZEt7hfySMg-a3GN-nfZmbW7o"

	var keys []jwk.Key
	for _, raw := range []string{"first_secret", "second_secret", "third_secret", "static_secret", "invalid_secret"} {
		key, err := jwk.FromRaw([]byte(raw))
		if !assert.NoError(t, err, `jwk.FromRaw for first key should succeed`) {
			return
		}
		_ = key.Set("alg", jwa.HS256)
		_ = key.Set("kid", strings.Replace(raw, "_secret", "One", 1))
		keys = append(keys, key)
	}

	validKeys := jwk.NewSet()
	for i := 0; i < 2; i++ {
		validKeys.AddKey(keys[i])
	}

	invalidKeys := jwk.NewSet()
	invalidKeys.AddKey(keys[2])

	staticSecret := keys[3]
	invalidStaticSecret := keys[4]

	for _, tc := range []struct {
		expErrCode int // 0 for Success
		config     jwx.Config
		hdrAuth    string
		info       string
	}{
		{
			hdrAuth: jwx.DefaultConfig.AuthScheme + " " + firstToken,
			config:  jwx.Config{KeySet: validKeys},
			info:    "First token valid",
		},
		{
			hdrAuth: jwx.DefaultConfig.AuthScheme + " " + secondToken,
			config:  jwx.Config{KeySet: validKeys},
			info:    "Second token valid",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    jwx.DefaultConfig.AuthScheme + " " + wrongToken,
			config:     jwx.Config{KeySet: validKeys},
			info:       "Wrong key id token",
		},
		{
			hdrAuth: jwx.DefaultConfig.AuthScheme + " " + staticToken,
			config:  jwx.Config{Key: staticSecret},
			info:    "Valid static secret token",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    jwx.DefaultConfig.AuthScheme + " " + staticToken,
			config:     jwx.Config{Key: invalidStaticSecret},
			info:       "Invalid static secret",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    jwx.DefaultConfig.AuthScheme + " " + firstToken,
			config:     jwx.Config{KeySet: invalidKeys},
			info:       "Invalid keys first token",
		},
		{
			expErrCode: http.StatusUnauthorized,
			hdrAuth:    jwx.DefaultConfig.AuthScheme + " " + secondToken,
			config:     jwx.Config{KeySet: invalidKeys},
			info:       "Invalid keys second token",
		},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		req.Header.Set(echo.HeaderAuthorization, tc.hdrAuth)
		c := e.NewContext(req, res)

		if tc.expErrCode != 0 {
			h := jwx.WithConfig(tc.config)(handler)
			he := h(c).(*echo.HTTPError)
			test.Equal(tc.expErrCode, he.Code, tc.info)
			continue
		}

		h := jwx.WithConfig(tc.config)(handler)
		if assert.NoError(t, h(c), tc.info) {
			user := c.Get("user").(jwt.Token)
			{
				v, ok := user.Get("name")
				if !assert.True(t, ok, `'name' field should exist`) {
					return
				}
				if !assert.Equal(t, v, "John Doe", tc.info) {
					return
				}
			}

			{
				v, ok := user.Get("admin")
				if ok {
					if !assert.Equal(t, v, true, tc.info) {
						return
					}
				}
			}
		}
	}
}

func ExampleEcho() {
	const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := echo.New()

	ar := jwk.NewCache(ctx)
	ar.Register(`https://www.googleapis.com/oauth2/v3/certs`, jwk.WithMinRefreshInterval(15*time.Minute))
	ks, err := ar.Refresh(ctx, googleCerts)
	if err != nil {
		panic(fmt.Sprintf("failed to refresh google JWKS: %s\n", err))
	}

	e.Use(jwx.JWX(ks))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	_ = e.Start(":8000")
}
