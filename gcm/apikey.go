package gcm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// ApiKeyLoader GCP service accountからaccess tokenを生成するが、一定期間はキャッシュする
type ApiKeyLoader struct {
	lastApiKey     string
	lastModifiedAt time.Time
	mtx            sync.Mutex
}

func NewApiKeyLoader() *ApiKeyLoader {
	return &ApiKeyLoader{}
}

func (l *ApiKeyLoader) Load() (string, error) {
	if l.lastModifiedAt.After(time.Now().Add(-10 * time.Minute)) {
		return l.lastApiKey, nil
	}

	l.mtx.Lock()
	defer l.mtx.Unlock()

	apiKey, err := l.load()
	if err != nil {
		return "", err
	}
	l.lastApiKey = apiKey
	l.lastModifiedAt = time.Now()
	return l.lastApiKey, nil
}

func (l *ApiKeyLoader) load() (string, error) {
	sa := os.Getenv("SERVICE_ACCOUNT")
	scope := "https://www.googleapis.com/auth/cloud-platform"
	buf := &bytes.Buffer{}
	err := getAccessTokenFromImpersonatedCredentials(buf, sa, scope)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// getAccessTokenFromImpersonatedCredentials uses a service account (SA1) to impersonate
// another service account (SA2) and obtain OAuth2 token for the impersonated account.
// To obtain a token for SA2, SA1 should have the "roles/iam.serviceAccountTokenCreator" permission on SA2.
func getAccessTokenFromImpersonatedCredentials(w io.Writer, impersonatedServiceAccount, scope string) error {
	// impersonatedServiceAccount := "name@project.service.gserviceaccount.com"
	// scope := "https://www.googleapis.com/auth/cloud-platform"

	ctx := context.Background()

	// Construct the GoogleCredentials object which obtains the default configuration from your
	// working environment.
	credentials, err := google.FindDefaultCredentials(ctx, scope)
	if err != nil {
		fmt.Fprintf(w, "failed to generate default credentials: %v", err)
		return fmt.Errorf("failed to generate default credentials: %w", err)
	}

	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: impersonatedServiceAccount,
		Scopes:          []string{scope},
		Lifetime:        60 * time.Minute,
		// delegates: The chained list of delegates required to grant the final accessToken.
		// For more information, see:
		// https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-permissions
		// Delegates is NOT USED here.
		Delegates: []string{},
	}, option.WithCredentials(credentials))
	if err != nil {
		return fmt.Errorf("CredentialsTokenSource error: %w", err)
	}

	// Get the OAuth2 token.
	// Once you've obtained the OAuth2 token, you can use it to make an authenticated call.
	t, err := ts.Token()
	if err != nil {
		fmt.Fprintf(w, "failed to receive token: %v", err)
		return fmt.Errorf("failed to receive token: %w", err)
	}
	fmt.Fprintf(w, "%s", t.AccessToken)

	return nil
}
