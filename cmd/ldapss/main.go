package main

import (
	"fmt"
	"ldap-self-service/internal/utils"
	"ldap-self-service/internal/view"
	"ldap-self-service/internal/web"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// for static files

const STATIC_PATH = "../static/"

func main() {
	config := utils.ReadConfig()
	view.SessionStart()
	routeHttp := mux.NewRouter()

	routeHttp.HandleFunc("/home", view.HandleHome)
	routeHttp.HandleFunc("/form", web.FormHandler)
	routeHttp.HandleFunc("/user", view.HandleUser)
	routeHttp.HandleFunc("/session/logout", view.HandleLogout)
	routeHttp.HandleFunc("/user/mail", view.HandleUserMail)
	routeHttp.HandleFunc("/user/wait", view.HandleUserWait)
	routeHttp.HandleFunc("/user/new", view.HandleInviteNewAccount)
	routeHttp.HandleFunc("/user/new/", view.HandleInviteNewAccount)
	routeHttp.HandleFunc("/passwd", view.HandlePasswd)
	routeHttp.HandleFunc("/passwd/lost", view.HandleLostPassword)
	routeHttp.HandleFunc("/passwd/lost/{code}", view.HandleFoundPassword)
	routeHttp.HandleFunc("/admin", view.HandleHome)
	routeHttp.HandleFunc("/admin/activate", view.HandleAdminActivateUsers)
	routeHttp.HandleFunc("/admin/unactivate/{cn}", view.HandleAdminUnactivateUser)
	routeHttp.HandleFunc("/admin/activate/{cn}", view.HandleAdminActivateUser)
	routeHttp.HandleFunc("/admin/users", view.HandleAdminUsers)
	routeHttp.HandleFunc("/admin/groups", view.HandleAdminGroups)
	routeHttp.HandleFunc("/admin/ldap/{dn}", view.HandleAdminLDAP)
	routeHttp.HandleFunc("/admin/create/{template}/{super_dn}", view.HandleAdminCreate)
	// staticFiles := http.StripPrefix("/static/", http.FileServer(http.Dir(STATIC_PATH)))
	// routeHttp.Handle("/static/", staticFiles)
	staticFiles := http.FileServer(http.Dir(STATIC_PATH))
	routeHttp.Handle("/static/{file:.*}", http.StripPrefix("/static/", staticFiles))
	routeHttp.Handle("/favicon.ico", staticFiles)

	// staticFiles := http.FileServer(http.Dir(staticPath))
	// http.Handle("/static/{file:.*}", http.StripPrefix("/static/", staticFiles))

	fmt.Printf("Starting server at port %s\n", config.HttpBindAddr)
	// if err := http.ListenAndServe(":8080", nil); err != nil {
	// 	log.Fatal(err)
	// }
	// if err := http.ListenAndServe(config.HttpBindAddr, logRequest(routeHttp)); err != nil {
	// 	log.Fatal(err)
	// }
	if err := http.ListenAndServe(config.HttpBindAddr, routeHttp); err != nil {
		log.Fatal(err)
	}

}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
