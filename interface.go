package jwx

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	ErrJWTInvalid = middleware.ErrJWTInvalid
	ErrJWTMissing = middleware.ErrJWTMissing
	ErrNoAuth     = echo.NewHTTPError(http.StatusUnauthorized, "no auth")
)

type (
	BeforeFunc                 = middleware.BeforeFunc
	JWTErrorHandler            = middleware.JWTErrorHandler
	JWTErrorHandlerWithContext = middleware.JWTErrorHandlerWithContext
	JWTSuccessHandler          = middleware.JWTSuccessHandler
	Skipper                    = middleware.Skipper
)

type jwtExtractor func(echo.Context) (string, error)

// Config defines the config for JWT middleware (using github.com/lestrrat-go/jwx/v2/jwt).
type Config struct {
	// Skipper defines a function to skip middleware.
	Skipper Skipper

	// BeforeFunc defines a function which is executed just before the middleware.
	BeforeFunc BeforeFunc

	// SuccessHandler defines a function which is executed for a valid token.
	SuccessHandler JWTSuccessHandler

	// Context key to store user information from the token into context.
	// Optional. Default value "user".
	ContextKey string

	// ErrorHandler defines a function which is executed for an invalid token.
	// It may be used to define a custom JWT error.
	ErrorHandler JWTErrorHandler

	// ErrorHandlerWithContext is almost identical to ErrorHandler, but it's passed the current context.
	ErrorHandlerWithContext JWTErrorHandlerWithContext

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "param:<name>"
	// - "cookie:<name>"
	// - "form:<name>"
	TokenLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	AuthScheme string

	// KeySet defines the JWKS that is used to verify the keys against.
	//
	// Each key in the JWKS must have a valid "alg" field.
	//
	// If the JWS message contains a "kid" field, one of the keys in the JWKS must have a matching "kid" (on top of the "alg" field) for the verification to succeed
	// If the key needs periodic rotation, use jwk.AutoRefresh
	KeySet jwk.Set

	// KeyFunc is a user-defined function that supplies the key or key set for
	// token verification.
	//
	// If you simply want to refresh the key(s) to verify the token with, consider using
	// `github.com/lestrrat-go/jwx/v2/jwk.AutoRefresh`, and set the key set in the KeySet field.
	KeyFunc func(echo.Context) (interface{}, error)

	// ValidateOptions defines the set of options to pass to jwt.Validate() in order to validate the JWT.
	//
	// See github.com/lestrrat-go/jwx/v2/jwt for the various options available.
	ValidateOptions []jwt.ValidateOption

	// TokenFactory is a function that creates a new instance of a token.
	// Use it to tell jwx to use a different underlying token type (such as github.com/lestrrat-go/jwx/v2/jwt/openid)
	//
	// Optional. Default function always creates a new token using jwt.New
	TokenFactory func(echo.Context) jwt.Token

	// Signing key to verify the token.
	//
	// If the key contains the "alg" header, its value is used when verifying the token.
	// Otherwise, the value in config.SignatureAlgorithm will be used.
	// If neither values are properly initialized, verification of the tokens will always fail.
	//
	// This is one of the three options to provide a token validation key.
	// The order of precedence is a user-defined KeyFunc, KeySet and Key.
	// Required if neither user-defined KeyFunc nor Keys is provided.
	Key jwk.Key

	// Signing algorithm used to verify the signature of the token
	// Optional. Default value HS256.
	SignatureAlgorithm jwa.SignatureAlgorithm

	// the actual list of extractors constructed from the configuration options
	extractors []jwtExtractor
}

func DefaultSkipper(c echo.Context) bool {
	return middleware.DefaultSkipper(c)
}
