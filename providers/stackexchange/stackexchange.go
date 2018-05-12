// Package stackexchange implements the OAuth2 protocol for authenticating users through Stackexchange.
package stackexchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/netcessities/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://stackexchange.com/oauth"
	tokenURL        string = "https://stackexchange.com/oauth/access_token/json"
	endpointProfile string = "https://api.stackexchange.com/me?site=stackoverflow"
)

// New creates a new StackExchange provider, and sets up important connection details.
// You should always call `stackexchange.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, clientAccessKey, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		ClientAccessKey:    clientAccessKey,
		CallbackURL:  callbackURL,
		providerName: "stackexchange",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Facebook.
type Provider struct {
	ClientKey    string
	Secret       string
	ClientAccessKey	string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the facebook package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Facebook for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	aurl := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: aurl,
	}
	return session, nil
}

// FetchUser will go to Facebook and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	// always add appsecretProof to make calls more protected
	// https://github.com/netcessities/goth/issues/96
	// https://developers.facebook.com/docs/graph-api/securing-requests
	hash := hmac.New(sha256.New, []byte(p.Secret))
	hash.Write([]byte(sess.AccessToken))
	appsecretProof := hex.EncodeToString(hash.Sum(nil))

	response, err := p.Client().Get(endpointProfile + "&access_token=" + url.QueryEscape(sess.AccessToken) + "&key=" + p.ClientAccessKey + "&appsecret_proof=" + appsecretProof)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		Items	[]struct {
			ID        int `json:"user_id"`
			Email     string `json:"email"`
			About     string `json:"about_me"`
			Name      string `json:"display_name"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Link      string `json:"link"`
			Picture   string `json:"profile_image"`
			Location  string `json:"location"`
		}
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Items[0].Name
	user.FirstName = u.Items[0].FirstName
	user.LastName = u.Items[0].LastName
	user.NickName = u.Items[0].Name
	user.Email = u.Items[0].Email
	user.Description = u.Items[0].About
	user.AvatarURL = u.Items[0].Picture
	user.UserID = strconv.Itoa(u.Items[0].ID)
	user.Location = u.Items[0].Location

	return err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{
			"private_info",
		},
	}

	defaultScopes := map[string]struct{}{
		"private_info": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

//RefreshToken refresh token is not provided by facebook
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by stackexchange")
}

//RefreshTokenAvailable refresh token is not provided by facebook
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
