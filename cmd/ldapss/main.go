package main

import (
	"fmt"
	"ldap-self-service/internal/view"
	"ldap-self-service/internal/web"
	"log"
	"net/http"
)

// for static files

var staticPath = "/mnt/d/work/ldap-self-service/static/"

func main() {
	view.SessionStart()
	handler := http.StripPrefix("/static/", http.FileServer(http.Dir("../static")))
	http.Handle("/static/", handler)
	http.Handle("/favicon.ico", handler)
	http.HandleFunc("/home", view.HandleHome)
	http.HandleFunc("/form", web.FormHandler)
	http.HandleFunc("/user", view.HandleUser)
	http.HandleFunc("/session/logout", view.HandleLogout)

	// staticFiles := http.FileServer(http.Dir(staticPath))
	// http.Handle("/static/{file:.*}", http.StripPrefix("/static/", staticFiles))

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
