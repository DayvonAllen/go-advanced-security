package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// hash/sign value
func getCode(msg string) string {
	h := hmac.New(sha256.New, []byte("djjdjdjdjdjdjdj dkdskksjdjdjdkskk18822893"))
	h.Write([]byte(msg))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func main() {
	http.HandleFunc("/", foo)
	http.HandleFunc("/submit", bar)
	http.ListenAndServe(":8080", nil)
}

func bar(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	email := req.FormValue(("email "))

	if email == "" {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	// hash email
	code := getCode(email)

	c := http.Cookie{
		Name:  "session",
		Value: code + "|" + email,
	}

	//address of cookie is the second parameter
	http.SetCookie(res, &c)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func foo(res http.ResponseWriter, req *http.Request) {
	c, err := req.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	// last arg is at most how many things will
	// it split into
	xs := strings.SplitN(c.Value, "|", 2)

	isEqual := false

	// compares hashed emails
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]

		code := getCode(cEmail)

		isEqual = hmac.Equal([]byte(cCode), []byte(code))
	}

	if isEqual {
		fmt.Println("You are logged in!")
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
	io.WriteString(res, html)
}
