package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2/github"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

//mock database table
// key is github ID, value is our database user ID
var githubConnections map[string]string

// unmarshal github response
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		}`json:"viewer"`
	}`json:"data"`
}

// we first start by creating a config struct
// client id provided by oauth provider
var githubOauthConfig = &oauth2.Config{
	ClientID: "661ed7450df8352ad7fc",
	// delete this
	ClientSecret: "dldlldldldldllddldlldlldld",
	Endpoint: github.Endpoint,
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/github", startGithubOauth)
	http.HandleFunc("/oauth2/receive", completeGithubOauth)
	_ = http.ListenAndServe(":8080", nil)
}

func completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	// we get code and state from query params
	code := r.FormValue("code")
	state := r.FormValue("state")

	// id from database or UUID
	if state != "0000" {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	// takes in a context from request and code, returns a token
	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	// takes in context and token and returns a tokenSource
	tokenSource := githubOauthConfig.TokenSource(r.Context(), token)

	// takes a context and a tokenSource and returns an httpClient
	httpClient := oauth2.NewClient(r.Context(), tokenSource)

	// converts any string into a reader
	// viewer is currently authenticated user
	// get the id of the viewer
	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"`)
	// everything is a post for graphql
	res, err := httpClient.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	// takes in a reader and gives you back all the bytes from it
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		http.Error(w, "Error!", http.StatusInternalServerError)
		return
	}

	var dataResponse githubResponse
	err = json.NewDecoder(res.Body).Decode(&dataResponse)
	if err != nil {
		http.Error(w, "Error!", http.StatusInternalServerError)
		return
	}

	githubID := dataResponse.Data.Viewer.ID

	userID, ok := githubConnections[githubID]
	if !ok {
		//create a new user account
		//maybe return maybe not depending on whether you want
		// to log them in after registering or not
	}

	// login to account userID using JWT
	log.Println(userID)
}

func startGithubOauth(w http.ResponseWriter, r *http.Request) {
	// param is state and that is associated with this particular login attempt
	// should be unique, like user id or UUID
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func index(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC mac</title>
	</head>
	<body>
		<form action="/oauth/github" method="POST">
			<input type="submit"  value="Login with Github"/>
		</form>
	</body>
	</html>
	`
	_, err := fmt.Fprint(w, html)
	if err != nil {
		panic(err)
	}
}