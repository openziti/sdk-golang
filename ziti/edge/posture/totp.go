package posture

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TotpCodeResult represents the outcome of requesting a TOTP code from a user or provider,
// containing either the code string or an error if the request failed.
type TotpCodeResult struct {
	Code string
	Err  error
}

// TotpTokenResult represents the outcome of exchanging a TOTP code for a session token,
// including the token value, issuance timestamp, and any errors encountered.
type TotpTokenResult struct {
	Token    string
	IssuedAt time.Time
	Err      error
}

// TotpCodeProvider defines the interface for obtaining TOTP codes, typically implemented
// by user interaction handlers that prompt for authenticator app codes.
type TotpCodeProvider interface {
	GetTotpCode() <-chan TotpCodeResult
}

// TotpTokenRequestor defines the interface for exchanging TOTP codes with the authentication
// service to obtain session tokens.
type TotpTokenRequestor interface {
	RequestTotpToken(code string) <-chan TotpTokenResult
}

// TotpTokenProvider abstracts the complete TOTP authentication flow, handling both code
// acquisition and token exchange.
type TotpTokenProvider interface {
	Request() <-chan TotpTokenResult
}

// TotpTokenProviderFunc is a function adapter that implements TotpTokenProvider, allowing
// simple functions to satisfy the interface.
type TotpTokenProviderFunc func() <-chan TotpTokenResult

func (f TotpTokenProviderFunc) Request() <-chan TotpTokenResult {
	return f()
}

// SingularTokenRequestor ensures only one TOTP token request is active at a time,
// preventing duplicate authentication attempts when multiple operations require TOTP.
type SingularTokenRequestor struct {
	isRequesting   sync.Mutex
	codeProvider   TotpCodeProvider
	tokenRequestor TotpTokenRequestor
}

const totpCodeProviderTimeout = 5 * time.Minute
const totpTokenRequestorTimeout = 30 * time.Second

// NewSingularTokenRequestor creates a requestor that coordinates TOTP code collection
// and token exchange while preventing concurrent requests.
func NewSingularTokenRequestor(codeProvider TotpCodeProvider, tokenRequestor TotpTokenRequestor) *SingularTokenRequestor {
	return &SingularTokenRequestor{
		codeProvider:   codeProvider,
		tokenRequestor: tokenRequestor,
	}
}

// Request initiates a TOTP token request if none is in progress, returning nil if a request
// is already active. The returned channel delivers the token result once the code is
// collected and exchanged, or an error if the process times out or fails.
func (r *SingularTokenRequestor) Request() <-chan TotpTokenResult {
	if lockObtained := r.isRequesting.TryLock(); !lockObtained {
		//outstanding request don't do anything
		return nil
	}

	tokenCh := make(chan TotpTokenResult)
	codeCh := r.codeProvider.GetTotpCode()

	go func() {
		defer r.isRequesting.Unlock()

		select {
		case codeResult := <-codeCh:
			if codeResult.Err != nil {
				tokenCh <- TotpTokenResult{
					Token: "",
					Err:   fmt.Errorf("error getting totp code: %v", codeResult.Err),
				}
				return
			}
			code := strings.TrimSpace(codeResult.Code)

			if code == "" {
				tokenCh <- TotpTokenResult{
					Token: "",
					Err:   errors.New("empty totp code entered"),
				}
				return
			}

			select {
			case tokenResult := <-r.tokenRequestor.RequestTotpToken(code):
				tokenCh <- tokenResult
			case <-time.After(totpTokenRequestorTimeout):
				tokenCh <- TotpTokenResult{
					Token: "",
					Err:   errors.New("timed out waiting for totp token"),
				}
				return
			}

			return
		case <-time.After(totpCodeProviderTimeout):
			tokenCh <- TotpTokenResult{
				Token: "",
				Err:   errors.New("timed out waiting for totp code"),
			}
			return
		}
	}()

	return tokenCh
}
