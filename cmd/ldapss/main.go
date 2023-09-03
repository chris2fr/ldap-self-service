package main

import (
	"fmt"
	"ldap-self-service/internal/view"
	"ldap-self-service/internal/web"
	"log"
	"net/http"
)

// for static files

const STATIC_PATH = "../static/"

func main() {
	view.SessionStart()
	handler := http.StripPrefix("/static/", http.FileServer(http.Dir(STATIC_PATH)))
	http.Handle("/static/", handler)
	http.Handle("/favicon.ico", handler)
	http.HandleFunc("/home", view.HandleHome)
	http.HandleFunc("/form", web.FormHandler)
	http.HandleFunc("/user", view.HandleUser)
	http.HandleFunc("/session/logout", view.HandleLogout)
	http.HandleFunc("/user/mail", view.HandleUserMail)
	http.HandleFunc("/user/wait", view.HandleUserWait)
	http.HandleFunc("/user/new", view.HandleInviteNewAccount)
	http.HandleFunc("/user/new/", view.HandleInviteNewAccount)
	http.HandleFunc("/passwd", view.HandlePasswd)
	http.HandleFunc("/passwd/lost", view.HandleLostPassword)
	http.HandleFunc("/passwd/lost/{code}", view.HandleFoundPassword)
	http.HandleFunc("/admin", view.HandleHome)
	http.HandleFunc("/admin/activate", view.HandleAdminActivateUsers)
	http.HandleFunc("/admin/unactivate/{cn}", view.HandleAdminUnactivateUser)
	http.HandleFunc("/admin/activate/{cn}", view.HandleAdminActivateUser)
	http.HandleFunc("/admin/users", view.HandleAdminUsers)
	http.HandleFunc("/admin/groups", view.HandleAdminGroups)
	http.HandleFunc("/admin/ldap/{dn}", view.HandleAdminLDAP)
	http.HandleFunc("/admin/create/{template}/{super_dn}", view.HandleAdminCreate)

	// staticFiles := http.FileServer(http.Dir(staticPath))
	// http.Handle("/static/{file:.*}", http.StripPrefix("/static/", staticFiles))

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
