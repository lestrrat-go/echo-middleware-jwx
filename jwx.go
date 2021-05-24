package jwx

import (
	"errors"
	"fmt"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	// DefaultConfig is the default JWX auth middleware config.
	DefaultConfig = Config{
		Skipper:            DefaultSkipper,
		SignatureAlgorithm: jwa.HS256,
		ContextKey:         "user",
		TokenLookup:        "header:" + echo.HeaderAuthorization,
		AuthScheme:         "Bearer",
		TokenFactory:       defaultTokenFactory,
	}
)

func defaultTokenFactory(_ echo.Context) jwt.Token {
	return jwt.New()
}

func (config *Config) handleError(err error, c echo.Context) (error, bool) {
	if h := config.ErrorHandler; h != nil {
		return h(err), true
	}
	if h := config.ErrorHandlerWithContext; h != nil {
		return h(err, c), true
	}
	return nil, false
}

func (config *Config) parseToken(auth string, c echo.Context) (jwt.Token, error) {
	token := config.TokenFactory(c)

	var options []jwt.ParseOption

	options = append(options, jwt.WithToken(token))

	ks := config.KeySet
	key := config.Key

	if kf := config.KeyFunc; kf != nil {
		thing, err := kf(c)
		if err != nil {
			return nil, err // ooooh, the urge to wrap...
		}

		switch v := thing.(type) {
		case jwk.Set:
			ks = v
		case jwk.Key:
			key = v
		default:
			return nil, fmt.Errorf(`invalid value for KeyFunc return value: %T`, v)
		}
	}

	if ks != nil {
		options = append(options, jwt.WithKeySet(ks))
	} else if key != nil {
		alg := jwa.SignatureAlgorithm(key.Algorithm())
		if alg == "" {
			alg = config.SignatureAlgorithm
		}

		if alg == "" {
			return nil, errors.New(`no signature algorithm could be inferred (did you set SignatureAlgorithm, or did you make sure the key has an 'alg' field?)`)
		}
		options = append(options, jwt.WithVerify(alg, key))
	} else {
		return nil, errors.New(`neither jwk.Key nor jwk.Set available`)
	}

	if len(config.ValidateOptions) > 0 {
		options = append(options, jwt.WithValidate(true))
	}

	for _, option := range config.ValidateOptions {
		options = append(options, option)
	}

	if _, err := jwt.ParseString(auth, options...); err != nil {
		return nil, err
	}

	return token, nil
}

func JWX(v interface{}) echo.MiddlewareFunc {
	config := DefaultConfig
	switch v := v.(type) {
	case jwk.Set:
		config.KeySet = v
	case jwk.Key:
		config.Key = v
	case func(echo.Context) (interface{},error):
		config.KeyFunc = v
	default:
		panic(fmt.Sprintf("expected jwk.Key or jwk.Set or a KeyFunc: got %T", v))
	}

	return WithConfig(config)
}

func WithConfig(config Config) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = DefaultConfig.Skipper
	}

	if config.TokenFactory == nil {
		config.TokenFactory = DefaultConfig.TokenFactory
	}

	if config.TokenLookup == "" {
		config.TokenLookup = DefaultConfig.TokenLookup
	}

	if config.AuthScheme == "" {
		config.AuthScheme = DefaultConfig.AuthScheme
	}

	if config.SignatureAlgorithm == "" {
		config.SignatureAlgorithm = DefaultConfig.SignatureAlgorithm
	}

	if config.ContextKey == "" {
		config.ContextKey = DefaultConfig.ContextKey
	}

	sources := strings.Split(config.TokenLookup, ",")

	var extractors []jwtExtractor
	for _, source := range sources {
		parts := strings.Split(source, ":")

		switch parts[0] {
		case "query":
			extractors = append(extractors, jwxFromQuery(parts[1]))
		case "param":
			extractors = append(extractors, jwxFromParam(parts[1]))
		case "cookie":
			extractors = append(extractors, jwxFromCookie(parts[1]))
		case "form":
			extractors = append(extractors, jwxFromForm(parts[1]))
		case "header":
			extractors = append(extractors, jwxFromHeader(parts[1], config.AuthScheme))
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			if config.BeforeFunc != nil {
				config.BeforeFunc(c)
			}
			var auth string
			var err error
			for _, extractor := range extractors {
				// Extract token from extractor, if it's not fail break the loop and
				// set auth
				auth, err = extractor(c)
				if err == nil {
					break
				}
			}
			// If none of extractor has a token, handle error
			if err != nil {
				if herr, ok := config.handleError(err, c); ok {
					return herr
				}
				return err
			}
			if auth == "" {
				panic("no auth")
			}

			token, err := config.parseToken(auth, c)
			if err == nil {
				// Store user information from token into context.
				c.Set(config.ContextKey, token)
				if config.SuccessHandler != nil {
					config.SuccessHandler(c)
				}
				return next(c)
			}

			if herr, ok := config.handleError(err, c); ok {
				return herr
			}

			return &echo.HTTPError{
				Code:     ErrJWTInvalid.Code,
				Message:  ErrJWTInvalid.Message,
				Internal: err,
			}
		}
	}
}

// jwxFromHeader returns a `jwtExtractor` that extracts token from the request header.
func jwxFromHeader(header string, authScheme string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		auth := c.Request().Header.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrJWTMissing
	}
}

// jwxFromQuery returns a `jwtExtractor` that extracts token from the query string.
func jwxFromQuery(param string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(param)
		if token == "" {
			return "", ErrJWTMissing
		}
		return token, nil
	}
}

// jwxFromParam returns a `jwtExtractor` that extracts token from the url param string.
func jwxFromParam(param string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		token := c.Param(param)
		if token == "" {
			return "", ErrJWTMissing
		}
		return token, nil
	}
}

// jwxFromCookie returns a `jwtExtractor` that extracts token from the named cookie.
func jwxFromCookie(name string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", ErrJWTMissing
		}
		return cookie.Value, nil
	}
}

// jwxFromForm returns a `jwtExtractor` that extracts token from the form field.
func jwxFromForm(name string) jwtExtractor {
	return func(c echo.Context) (string, error) {
		field := c.FormValue(name)
		if field == "" {
			return "", ErrJWTMissing
		}
		return field, nil
	}
}
