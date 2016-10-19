package main

import (
	"fmt"
	"net/http"

	"github.com/justindh/gocrest"
	"github.com/justindh/gocrest/sso"
)

var s = sso.NewSSO(gocrest.TranquilityLogin, "http://localhost:3000/auth/completeHandshake", "0742798c09114519864815f07657fdbf", "G2bVkAkdgmScpNr9F1Xq7ErfOjm2NCsMLCZrkjc3", gocrest.DefaultUserAgent, []string{"characterLocationRead", "characterAccountRead"})

func main() {
	http.HandleFunc("/", getSSOUrl)
	http.HandleFunc("/auth/completeHandshake", catchHandshake)
	fmt.Println("Listening...")
	http.ListenAndServe(":3000", nil)
}

func getSSOUrl(w http.ResponseWriter, r *http.Request) {
	ssoURL, urlErr := s.GetAuthURI("randomvaluethatwevalidateonthewayback")
	if urlErr != nil {
		fmt.Fprintf(w, urlErr.Error())
		return
	}
	fmt.Println("ssoUrl", ssoURL.String())
	fmt.Fprint(w, ssoURL.String())
}

func catchHandshake(w http.ResponseWriter, r *http.Request) {
	oatr, err := s.GetToken(r.URL.Query().Get("code"), sso.TokenAuth)
	if err != nil {
		fmt.Print(err)
	}
	oavr, err := s.VerifyToken(oatr.AccessToken)
	if err != nil {
		fmt.Print(err)
		fmt.Fprintf(w, "Err response: %v", err)
	} else {
		fmt.Printf("Successful response from app.CompleteHandshake :: %+v\n", oavr)
		fmt.Fprintf(w, "Successful response from app.CompleteHandshake")
	}
}
