package sso

import (
	"testing"

	"github.com/justindh/gocrest"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetAuthURI(t *testing.T) {
	testServer := newServerFromFile("fixtures/fail", "/fail")
	defer testServer.Close()
	testState := "teststate"
	Convey("Setting up test sso", t, func() {
		tsso := NewSSO(testServer.URL, "http://localhost:3000/auth/completeHandshake", "0742798c09114519864815f07657fdbf", "G2bVkAkdgmScpNr9F1Xq7ErfOjm2NCsMLCZrkjc3", gocrest.DefaultUserAgent, []string{"characterLocationRead", "characterAccountRead"})
		res, err := tsso.GetAuthURI(testState)
		Convey("Should not have errors", func() {
			So(err, ShouldBeNil)
		})
		Convey("Path should be /oauth/authorize", func() {
			So(res.Path, ShouldEqual, "/oauth/authorize")
		})
		Convey("Query should be full of stuff", func() {
			So(res.RawQuery, ShouldEqual, "client_id=0742798c09114519864815f07657fdbf&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2FcompleteHandshake&response_type=code&scope=characterLocationRead+characterAccountRead&state=teststate")
		})
	})

}

func TestGetToken(t *testing.T) {
	testServer := newServerFromFile("fixtures/oauth/token", "/oauth/token")
	defer testServer.Close()
	Convey("Setting up test sso", t, func() {
		tsso := NewSSO(testServer.URL, "http://localhost:3000/auth/completeHandshake", "0742798c09114519864815f07657fdbf", "G2bVkAkdgmScpNr9F1Xq7ErfOjm2NCsMLCZrkjc3", gocrest.DefaultUserAgent, []string{"characterLocationRead", "characterAccountRead"})
		res, err := tsso.GetToken("testcode", TokenAuth)
		Convey("Should not have errors", func() {
			So(err, ShouldBeNil)
		})
		Convey("Test that data loaded", func() {
			So(res.AccessToken, ShouldEqual, "uNEEh...a_WpiaA2")
			So(res.ExpiresIn, ShouldEqual, 1200)
			So(res.RefreshToken, ShouldEqual, "gEy...fM0")
			So(res.TokenType, ShouldEqual, "Bearer")
		})
	})
}

func TestGetTokenFail(t *testing.T) {
	testServer := newServerFromFile("fixtures/fail", "/oauth/token")
	defer testServer.Close()
	Convey("Setting up test sso", t, func() {
		tsso := NewSSO(testServer.URL, "http://localhost:3000/auth/completeHandshake", "0742798c09114519864815f07657fdbf", "G2bVkAkdgmScpNr9F1Xq7ErfOjm2NCsMLCZrkjc3", gocrest.DefaultUserAgent, []string{"characterLocationRead", "characterAccountRead"})
		_, err := tsso.GetToken("testcode", TokenAuth)
		Convey("Should have errors", func() {
			So(err, ShouldNotBeNil)
		})
	})
}

func TestVerifyToken(t *testing.T) {
	testServer := newServerFromFile("fixtures/oauth/verify", "/oauth/verify")
	defer testServer.Close()
	Convey("Setting up test sso", t, func() {
		tsso := NewSSO(testServer.URL, "http://localhost:3000/auth/completeHandshake", "0742798c09114519864815f07657fdbf", "G2bVkAkdgmScpNr9F1Xq7ErfOjm2NCsMLCZrkjc3", gocrest.DefaultUserAgent, []string{"characterLocationRead", "characterAccountRead"})
		res, err := tsso.VerifyToken("testcode")
		Convey("Should not have errors", func() {
			So(err, ShouldBeNil)
		})
		Convey("Test that data loaded", func() {
			So(res.CharacterID, ShouldEqual, 273042051)
			So(res.CharacterName, ShouldEqual, "CCP illurkall")
			So(res.CharacterOwnerHash, ShouldEqual, "XM4D...FoY=")
			So(res.Scopes, ShouldEqual, " ")
			So(res.TokenType, ShouldEqual, "Character")
		})
	})
}
