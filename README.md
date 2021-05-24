# echo-middleware-jwx

JWT middleware for github.com/labstack/echo using github.com/lestrrat-go/jwx

WARNING: As of this writing, this is a proof of concept. The author does not usually develop web applications using github.com/labstack/echo. This library is provided in hopes that it will help you, but there may be bugs lurking. Contributions are welcome.

# DESCRIPTION

This is pretty much a straight port of `"github.com/labstack/echo/v4/middleware".JWT`, which uses `github.com/lestrrat-go/jwx` instead of `github.com/dgrijalva/jwt-go` to handle the JWT tokens.

Please note that there are few differences. You are advised to read the code before using it.

# SYNOPSIS

```go
func main() {
  const googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  e := echo.New()

  ar := jwk.NewAutoRefresh(ctx)
  ar.Configure(`https://www.googleapis.com/oauth2/v3/certs`, jwk.WithMinRefreshInterval(15*time.Minute))
  ks, err := ar.Refresh(ctx, googleCerts)
  if err != nil {
    panic(fmt.Sprintf("failed to refresh google JWKS: %s\n", err))
  }

  e.Use(jwx.JWX(ks))
  e.GET("/", func(c echo.Context) error {
    return c.String(http.StatusOK, "Hello, World!")
  })

  e.Start(":8000")
}
```
