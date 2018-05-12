package stackexchange_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/netcessities/goth"
	"github.com/netcessities/goth/providers/stackexchange"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := stackexchangeProvider()
	a.Equal(provider.ClientKey, os.Getenv("STACKEXCHANGE_KEY"))
	a.Equal(provider.Secret, os.Getenv("STACKEXCHANGE_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), stackexchangeProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := stackexchangeProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*stackexchange.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "stackexchange.com/dialog/oauth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("STACKEXCHANGE_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=private_info")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := stackexchangeProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://stackexchange.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*stackexchange.Session)
	a.Equal(session.AuthURL, "http://stackexchange.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func stackexchangeProvider() *stackexchange.Provider {
	return stackexchange.New(os.Getenv("STACKEXCHANGE_KEY"), os.Getenv("STACKEXCHANGE_SECRET"), "/foo", "private_info")
}
