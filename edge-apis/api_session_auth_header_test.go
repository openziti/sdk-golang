package edge_apis

import (
	"net/http"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// headerCapturingRequest records header params the way the openapi runtime's own request does:
// SetHeaderParam replaces the named header with every value it is given. Methods other than
// SetHeaderParam come from the embedded (nil) interface and panic if invoked.
type headerCapturingRequest struct {
	runtime.ClientRequest
	headers http.Header
}

func (r *headerCapturingRequest) SetHeaderParam(name string, values ...string) error {
	if r.headers == nil {
		r.headers = http.Header{}
	}
	r.headers[http.CanonicalHeaderKey(name)] = values
	return nil
}

func oidcSessionWithAltAuth(accessToken string, altAuth ...string) *ApiSessionOidc {
	requestHeaders := http.Header{}
	for _, value := range altAuth {
		requestHeaders.Add("Authorization", value)
	}

	return &ApiSessionOidc{
		OidcTokens: &oidc.Tokens[*oidc.IDTokenClaims]{
			Token: &oauth2.Token{AccessToken: accessToken},
		},
		RequestHeaders: requestHeaders,
	}
}

// Secondary external JWTs are added one at a time with AddRequestHeader, so http.Header holds
// several values under Authorization and all of them are auth header candidates.
func TestApiSessionOidcSendsEveryAltAuthHeader(t *testing.T) {
	t.Run("every alternate value is sent alongside the access token", func(t *testing.T) {
		session := oidcSessionWithAltAuth("access-token", "Bearer alt-one", "Bearer alt-two")
		request := &headerCapturingRequest{}

		require.NoError(t, session.AuthenticateRequest(request, strfmt.Default))

		require.Equal(t, []string{
			"Bearer access-token",
			"Bearer alt-one",
			"Bearer alt-two",
		}, request.headers.Values("Authorization"))
	})

	t.Run("a single alternate value still rides along", func(t *testing.T) {
		session := oidcSessionWithAltAuth("access-token", "Bearer alt-one")
		request := &headerCapturingRequest{}

		require.NoError(t, session.AuthenticateRequest(request, strfmt.Default))

		require.Equal(t, []string{
			"Bearer access-token",
			"Bearer alt-one",
		}, request.headers.Values("Authorization"))
	})

	t.Run("no alternates leaves just the access token", func(t *testing.T) {
		session := oidcSessionWithAltAuth("access-token")
		request := &headerCapturingRequest{}

		require.NoError(t, session.AuthenticateRequest(request, strfmt.Default))

		require.Equal(t, []string{"Bearer access-token"}, request.headers.Values("Authorization"))
	})
}
