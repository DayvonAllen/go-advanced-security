package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type myClaims struct {
	jwt.StandardClaims
	Email string
}

var newKey = make([]byte, 64)
var _, _ = io.ReadFull(rand.Reader, newKey)

func getJWT(msg string) (string, error){

	claims := myClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		Email: msg,
	}
	// always better to use a pointer with JSON
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	signedString, err := token.SignedString(newKey)

	if err != nil {
		return "", fmt.Errorf("%w", err)
	}
	return signedString, nil
}

func main() {
	http.HandleFunc("/", foo)
	http.HandleFunc("/submit", bar)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

func bar(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue("email ")

	if email == "" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	signedString, err := getJWT(email)
	if err != nil {
		http.Error(res, "Couldn't get JWT", http.StatusInternalServerError)
		return
	}

	c := http.Cookie{
		Name:  "session",
		Value: "bearer " + signedString,
	}

	http.SetCookie(res, &c)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func foo(res http.ResponseWriter, req *http.Request) {
	c, err := req.Cookie("session")
	//if there is no cookie we set an empty cookie
	if err != nil {
		c = &http.Cookie{}
	}

	signedString := c.Value
	//last arg is at most how many things will
	//it split into
	xs := strings.SplitN(signedString, " ", 2)

	var jwtValue string
	//isEqual := false

	if len(xs) == 2 {
		jwtValue = xs[1]
	}

	token, err := jwt.ParseWithClaims(jwtValue, &myClaims{},func(t *jwt.Token)(interface{}, error) {
		if t.Method.Alg() == jwt.SigningMethodHS256.Alg() {
			//verify token(we pass in our key to be verified)
			return newKey, nil
		}
		return nil, fmt.Errorf("Invalid signing method")
	})

	if err != nil {
		http.Error(res, "Invalid token", http.StatusUnauthorized)
		return
	}

	// determine whether the token is valid
	// parse calls the valid method on the claims interface(which includes the standardClaims)
	// the property Valid on token is the result of that call
	// standard valid just makes sure it's a proper token that
	// hasn't expired yet
	isEqual := token.Valid

	if isEqual {
		// logged in at this point
		// because we receive an interface type we need to assert which type we want to use that inherits it
		claims := token.Claims.(*myClaims)

		fmt.Println(claims.Email)
		fmt.Println(claims.ExpiresAt)
	}

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
		<form action="/submit" method="POST">
			<input type="text" name="email"/>
			<input type="submit" />
		</form>
	</body>
	</html>
	`
	_, _ = io.WriteString(res, html)
}
