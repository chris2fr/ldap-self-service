package view

import (

	"crypto/rand"



	"fmt"
	"ldap-self-service/internal/user"
	"ldap-self-service/internal/utils"
	"log"
	"net/http"
	"strings"


	"github.com/go-ldap/ldap/v3"

	"github.com/gorilla/sessions"

)

// For sessions
var store sessions.Store = nil

func StartSession() {
	// enable sessions
	var session_key = make([]byte, 32)

	n, err := rand.Read(session_key)
	if err != nil || n != 32 {
		log.Fatal(err)
	}
	store = sessions.NewCookieStore(session_key)
	// This puts the config in a global variable
}

func HandleLogin(w http.ResponseWriter, r *http.Request) *LoginInfo {
	templateLogin := getTemplate("login.html")
	config := utils.ReadConfig()

	if r.Method == "POST" {
		// log.Printf("%v", "Parsing Form HandleLogin")
		r.ParseForm()

		username := strings.Join(r.Form["username"], "")
		password := strings.Join(r.Form["password"], "")
		config := utils.ReadConfig()
		user_dn := fmt.Sprintf("%s=%s,%s", config.UserNameAttr, username, config.UserBaseDN)

		// log.Printf("%v", user_dn)
		// log.Printf("%v", username)

		if strings.EqualFold(username, config.AdminAccount) {
			user_dn = username
		}
		loginInfo, err := DoLogin(w, r, username, user_dn, password)
		// log.Printf("%v", loginInfo)
		if err != nil {
			data := &LoginFormData{
				Username: username,
				Common: NestedCommonTplData{
					CanAdmin:  false,
					CanInvite: true,
					LoggedIn:  false,
				},
			}
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				data.WrongPass = true
			} else if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				data.WrongUser = true
			} else {
				log.Printf("%v", err)
				log.Printf("%v", user_dn)
				log.Printf("%v", username)
				data.Common.ErrorMessage = err.Error()
			}
			// templateLogin.Execute(w, data)

			execTemplate(w, templateLogin, data.Common, NestedLoginTplData{}, config, data)
		}
		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
		return loginInfo

	} else if r.Method == "GET" {
		execTemplate(w, templateLogin, NestedCommonTplData{
			CanAdmin:  false,
			CanInvite: true,
			LoggedIn:  false}, NestedLoginTplData{}, config, LoginFormData{
			Common: NestedCommonTplData{
				CanAdmin:  false,
				CanInvite: true,
				LoggedIn:  false}})
		// templateLogin.Execute(w, LoginFormData{
		// 	Common: NestedCommonTplData{
		// 		CanAdmin:  false,
		// 		CanInvite: true,
		// 		LoggedIn:  false}})
		return nil
	} else {
		http.Error(w, "Unsupported method", http.StatusBadRequest)
		return nil
	}
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {

	err := Logout(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/home", http.StatusFound)
}

func checkLogin(w http.ResponseWriter, r *http.Request) *LoginStatus {
	config := utils.ReadConfig()
	var login_info *LoginInfo
	// log.Printf("checkLogin")
	l, err := utils.LdapOpen(w)
	// log.Printf("checkLogin")
	if l == nil {
		return nil
	}
	session, err := store.Get(r, "guichet_session")
	if err != nil {
		log.Printf("checkLogin ldapOpen : %v", err)
		log.Printf("checkLogin ldapOpen : %v", session)
		log.Printf("checkLogin ldapOpen : %v", session.Values)
		return nil
	}
	// log.Printf("checkLogin")
	username, ok := session.Values["login_username"]
	password, ok2 := session.Values["login_password"]
	user_dn, ok3 := session.Values["login_dn"]

	if ok && ok2 && ok3 {
		login_info = &LoginInfo{
			DN:       user_dn.(string),
			Username: username.(string),
			Password: password.(string),
		}
		err = user.Bind(user.User{
			DN:       login_info.DN,
			Password: login_info.Password,
		}, &config, l)
		if err != nil {
			delete(session.Values, "login_username")
			delete(session.Values, "login_password")
			delete(session.Values, "login_dn")

			err = session.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil
			}
			return checkLogin(w, r)
		}
		ldapUser, err := user.Get(user.User{
			DN: login_info.DN,
			CN: login_info.Username,
		}, &config, l)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}
		userEntry := ldapUser.UserEntry
		loginStatus := LoginStatus{
			Info:      login_info,
			conn:      l,
			UserEntry: userEntry,
			Common: NestedCommonTplData{
				CanAdmin:  ldapUser.CanAdmin,
				CanInvite: ldapUser.CanInvite,
			},
		}
		// log.Printf("checkLogin %v %v", loginStatus, loginStatus.Info)
		return &loginStatus
	} else {
		return nil
	}
}

func checkInviterLogin(w http.ResponseWriter, r *http.Request) *LoginStatus {

	login := checkLogin(w, r)
	if login == nil {
		return nil
	}

	// if !login.CanInvite {
	// 	http.Error(w, "Not authorized to invite new users.", http.StatusUnauthorized)
	// 	return nil
	// }

	return login
}

func SessionStart() {
	// enable sessions
	session_key := make([]byte, 32)
	n, err := rand.Read(session_key)
	if err != nil || n != 32 {
		log.Fatal(err)
	}

	store = sessions.NewCookieStore(session_key)

}

func checkAdminLogin(w http.ResponseWriter, r *http.Request) *LoginStatus {
	login := checkLogin(w, r)
	if login == nil {
		return nil
	}

	if !login.Common.CanAdmin {
		http.Error(w, "Not authorized to perform administrative operations.", http.StatusUnauthorized)
		return nil
	}
	return login
}

func DoLogin(w http.ResponseWriter, r *http.Request, username string, user_dn string, password string) (*LoginInfo, error) {
	l, _ := utils.LdapOpen(w)

	err := l.Bind(user_dn, password)
	if err != nil {
		log.Printf("doLogin : %v", err)
		log.Printf("doLogin : %v", user_dn)
		return nil, err
	}

	// Successfully logged in, save it to session
	session, err := store.Get(r, "guichet_session")
	if err != nil {
		session, _ = store.New(r, "guichet_session")
	}

	session.Values["login_username"] = username
	session.Values["login_password"] = password
	session.Values["login_dn"] = user_dn
	// log.Printf("Do Login %v %v", user_dn, username)
	err = session.Save(r, w)
	if err != nil {
		log.Printf("doLogin Session Save: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, err
	}

	LoginInfo := LoginInfo{
		DN:       user_dn,
		Username: username,
		Password: password,
	}

	return &LoginInfo, nil
}

func Logout(w http.ResponseWriter, r *http.Request) error {
	// log.Printf("Logout %v", "guichet_session")
	session, err := store.Get(r, "guichet_session")
	if err != nil {
		session, _ = store.New(r, "guichet_session")
		// return err
	} else {
		delete(session.Values, "login_username")
		delete(session.Values, "login_password")
		delete(session.Values, "login_dn")

		err = session.Save(r, w)
	}

	// return err
	return nil
}

// New account creation directly from interface

func OpenNewUserLdap(config *utils.ConfigFile) (*ldap.Conn, error) {
	l, err := utils.OpenLdap(config)
	if err != nil {
		log.Printf("openNewUserLdap 1 : %v %v", err, l)
		log.Printf("openNewUserLdap 1 : %v", config)
		// data.Common.ErrorMessage = err.Error()
	}
	err = l.Bind(config.NewUserDN, config.NewUserPassword)
	if err != nil {
		log.Printf("openNewUserLdap Bind : %v", err)
		log.Printf("openNewUserLdap Bind : %v", config.NewUserDN)
		log.Printf("openNewUserLdap Bind : %v", config.NewUserPassword)
		log.Printf("openNewUserLdap Bind : %v", config)
		// data.Common.ErrorMessage = err.Error()
	}
	return l, err
}
