package view

import (
	"bytes"
	"crypto/rand"
	"regexp"

	b64 "encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"ldap-self-service/internal/user"
	"ldap-self-service/internal/utils"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/argon2"
)

// For the template engine
var templatePath = "../templates"

// For sessions
var store sessions.Store = nil

// Configure for github.com/gorilla/sessions

var EMAIL_REGEXP = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

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

func HandleLogout(w http.ResponseWriter, r *http.Request) {

	err := Logout(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/home", http.StatusFound)
}

func HandleHome(w http.ResponseWriter, r *http.Request) {

	templateHome := getTemplate("home.html")
	config := utils.ReadConfig()

	loginStatus := checkLogin(w, r)

	if loginStatus == nil {
		if HandleLogin(w, r) == nil {
			return
		}
		loginStatus = checkLogin(w, r)
	}
	// loginInfo := loginStatus.Info

	can_admin := false
	if loginStatus != nil {
		can_admin = loginStatus.Common.CanAdmin
	}

	// log.Printf("handleHome: %v", loginStatus.Info)

	data := HomePageData{
		Login: NestedLoginTplData{
			Login: loginStatus,
		},
		BaseDN: config.BaseDN,
		Org:    config.Org,
		Common: NestedCommonTplData{
			CanAdmin:  can_admin,
			CanInvite: true,
			LoggedIn:  true,
		},
	}
	execTemplate(w, templateHome, data.Common, data.Login, config, data)
	// templateHome.Execute(w, data)

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

func Add(curUser user.User, config *utils.ConfigFile, ldapConn *ldap.Conn) error {
	log.Printf(fmt.Sprint("Adding New User"))
	// LDAP Add Object
	dn := curUser.DN
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	if curUser.DisplayName != "" {
		req.Attribute("displayName", []string{curUser.DisplayName})
	}
	if curUser.GivenName != "" {
		req.Attribute("givenName", []string{curUser.GivenName})
	}
	if curUser.Mail != "" {
		req.Attribute("mail", []string{curUser.Mail})
	}
	if curUser.UID != "" {
		req.Attribute("uid", []string{curUser.UID})
	}
	// if curUser.Member != "" {
	// 	req.Attribute("member", []string{curUser.Member})
	// }
	if curUser.SN != "" {
		req.Attribute("sn", []string{curUser.SN})
	}
	if curUser.OtherMailbox != "" {
		req.Attribute("carLicense", []string{curUser.OtherMailbox})
	}
	if curUser.Description != "" {
		req.Attribute("description", []string{curUser.Description})
	}
	// Add the User
	// err := ldapConn.Add(req)
	// var ldapNewConn *ldap.Conn
	ldapNewConn, err := OpenNewUserLdap(config)
	err = ldapNewConn.Add(req)
	if err != nil {
		log.Printf(fmt.Sprintf("add(User) ldapconn.Add: %v", err))
		log.Printf(fmt.Sprintf("add(User) ldapconn.Add: %v", req))
		log.Printf(fmt.Sprintf("add(User) ldapconn.Add: %v", curUser))
		//return err
	}
	// passwordModifyRequest := ldap.NewPasswordModifyRequest(curUser.DN, "", curUser.Password)
	// _, err = ldapConn.PasswordModify(passwordModifyRequest)
	// if err != nil {
	// 	return err
	// }

	// Send the email

	newUserLdapConn, _ := OpenNewUserLdap(config)
	curUser.OtherMailbox = ""
	err = PasswordLost(curUser, config, newUserLdapConn)
	if err != nil {
		log.Printf("add User PasswordLost %v", err)
		log.Printf("add User PasswordLost %v", newUserLdapConn)
	}

	// sendMailTplData := SendMailTplData{
	// 	From:            "alice@resdigita.org",
	// 	To:              curUser.OtherMailbox,
	// 	RelTemplatePath: "curUser/new.email.txt",
	// 	EmailContentVars: EmailContentVarsTplData{
	// 		InviteFrom:  "alice@resdigita.org",
	// 		SendAddress: "https://www.gvoisins.org",
	// 		Code:        "...",
	// 	},
	// }
	// err = sendMail(sendMailTplData)
	// if err != nil {
	// 	log.Printf("add(curUser) sendMail: %v", err)
	// 	log.Printf("add(curUser) sendMail: %v", curUser)
	// 	log.Printf("add(curUser) sendMail: %v", sendMailTplData)
	// }
	return err
}

func PasswordLost(curUser user.User, config *utils.ConfigFile, ldapConn *ldap.Conn) error {
	if curUser.CN == "" && curUser.Mail == "" && curUser.OtherMailbox == "" {
		return errors.New("Il n'y a pas de quoi identifier l'utilisateur")
	}
	searchFilter := "(|"
	if curUser.CN != "" {
		searchFilter += "(cn=" + curUser.UID + ")"
	}
	if curUser.Mail != "" {
		searchFilter += "(mail=" + curUser.Mail + ")"
	}
	if curUser.OtherMailbox != "" {
		searchFilter += "(carLicense=" + curUser.OtherMailbox + ")"
	}
	searchFilter += ")"
	searchReq := ldap.NewSearchRequest(config.UserBaseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, searchFilter, []string{"cn", "uid", "mail", "carLicense", "sn", "displayName", "givenName"}, nil)
	searchRes, err := ldapConn.Search(searchReq)
	if err != nil {
		log.Printf("passwordLost search : %v %v", err, ldapConn)
		log.Printf("passwordLost search : %v", searchReq)
		log.Printf("passwordLost search : %v", searchRes)
		log.Printf("passwordLost search: %v", curUser)
		return err
	}
	if len(searchRes.Entries) == 0 {
		log.Printf("Il n'y a pas d'utilisateur qui correspond %v", searchReq)
		return errors.New("Il n'y a pas d'utilisateur qui correspond")
	}
	// log.Printf("passwordLost 58 : %v", curUser)
	// log.Printf("passwordLost 59 : %v", searchRes.Entries[0])
	// log.Printf("passwordLost 60 : %v", searchRes.Entries[0].GetAttributeValue("cn"))
	// log.Printf("passwordLost 61 : %v", searchRes.Entries[0].GetAttributeValue("uid"))
	// log.Printf("passwordLost 62 : %v", searchRes.Entries[0].GetAttributeValue("mail"))
	// log.Printf("passwordLost 63 : %v", searchRes.Entries[0].GetAttributeValue("carLicense"))
	// Préparation du courriel à envoyer

	delReq := ldap.NewDelRequest("uid="+searchRes.Entries[0].GetAttributeValue("cn")+","+config.InvitationBaseDN, nil)
	err = ldapConn.Del(delReq)

	curUser.Password = utils.SuggestPassword()
	curUser.DN = "uid=" + searchRes.Entries[0].GetAttributeValue("cn") + "," + config.InvitationBaseDN
	curUser.UID = searchRes.Entries[0].GetAttributeValue("cn")
	curUser.CN = searchRes.Entries[0].GetAttributeValue("cn")
	curUser.Mail = searchRes.Entries[0].GetAttributeValue("mail")
	curUser.OtherMailbox = searchRes.Entries[0].GetAttributeValue("carLicense")
	code := b64.URLEncoding.EncodeToString([]byte(curUser.UID + ";" + curUser.Password))
	/* Check for outstanding invitation */
	searchReq = ldap.NewSearchRequest(config.InvitationBaseDN, ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false, "(uid="+curUser.UID+")", []string{"seeAlso"}, nil)
	searchRes, err = ldapConn.Search(searchReq)
	if err != nil {
		log.Printf(fmt.Sprintf("passwordLost (Check existing invitation) : %v", err))
		log.Printf(fmt.Sprintf("passwordLost (Check existing invitation) : %v", curUser))
		return err
	}
	// if len(searchRes.Entries) == 0 {
	/* Add the invitation */
	addReq := ldap.NewAddRequest(
		"uid="+curUser.UID+","+config.InvitationBaseDN,
		nil)
	addReq.Attribute("objectClass", []string{"top", "account", "simpleSecurityObject"})
	addReq.Attribute("uid", []string{curUser.UID})
	addReq.Attribute("userPassword", []string{curUser.Password})
	addReq.Attribute("seeAlso", []string{config.UserNameAttr + "=" + curUser.UID + "," + config.UserBaseDN})
	// Password invitation may already exist

	//
	err = ldapConn.Add(addReq)
	if err != nil {
		log.Printf("passwordLost 83 : %v", err)
		log.Printf("passwordLost 84 : %v", curUser)

		log.Printf("passwordLost 84 : %v", addReq)
		// // log.Printf("passwordLost 85 : %v", searchRes.Entries[0]))
		// // For some reason I get here even if the entry exists already
		// return err
	}
	// }
	ldapNewConn, err := OpenNewUserLdap(config)
	if err != nil {
		log.Printf("passwordLost openNewUserLdap : %v", err)
	}
	err = Passwd(curUser, config, ldapNewConn)
	if err != nil {
		log.Printf("passwordLost passwd : %v", err)
		log.Printf("passwordLost passwd : %v", curUser)
		log.Printf("passwordLost passwd : %v", searchRes.Entries[0])
		return err
	}
	templateMail := template.Must(template.ParseFiles(templatePath + "/passwd/lost_password_email.txt"))
	buf := bytes.NewBuffer([]byte{})
	templateMail.Execute(buf, &CodeMailFields{
		To:             curUser.OtherMailbox,
		From:           config.MailFrom,
		InviteFrom:     curUser.UID,
		Code:           code,
		WebBaseAddress: config.WebAddress,
	})
	// message := []byte("Hi " + curUser.OtherMailbox)
	log.Printf("Sending mail to: %s", curUser.OtherMailbox)
	// var auth sasl.Client = nil
	// if config.SMTPUsername != "" {
	// 	auth = sasl.NewPlainClient("", config.SMTPUsername, config.SMTPPassword)
	// }
	message := buf.Bytes()
	auth := smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPServer)
	log.Printf("auth: %v", auth)
	err = smtp.SendMail(config.SMTPServer+":587", auth, config.SMTPUsername, []string{curUser.OtherMailbox}, message)
	if err != nil {
		log.Printf("email send error %v", err)
		return err
	}
	log.Printf("Mail sent.")
	return err
}

func Passwd(curUser user.User, config *utils.ConfigFile, ldapConn *ldap.Conn) error {
	passwordModifyRequest := ldap.NewPasswordModifyRequest(curUser.DN, "", curUser.Password)
	_, err := ldapConn.PasswordModify(passwordModifyRequest)
	if err != nil {
		log.Printf(fmt.Sprintf("model-user passwd : %v %v", err, ldapConn))
		log.Printf(fmt.Sprintf("model-user passwd : %v", curUser))
	}
	return err
}

func PasswordFound(curUser user.User, config *utils.ConfigFile, ldapConn *ldap.Conn) (string, error) {
	l, err := utils.OpenLdap(config)
	if err != nil {
		log.Printf("passwordFound openLdap %v", err)
		// log.Printf("passwordFound openLdap Config : %v", config)
		return "", err
	}
	if curUser.DN == "" && curUser.UID != "" {
		curUser.DN = "uid=" + curUser.UID + "," + config.InvitationBaseDN
	}
	err = l.Bind(curUser.DN, curUser.Password)
	if err != nil {
		log.Printf("passwordFound l.Bind %v", err)
		log.Printf("passwordFound l.Bind %v", curUser.DN)
		log.Printf("passwordFound l.Bind %v", curUser.UID)
		return "", err
	}
	searchReq := ldap.NewSearchRequest(curUser.DN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(uid="+curUser.UID+")", []string{"seeAlso"}, nil)
	var searchRes *ldap.SearchResult
	searchRes, err = ldapConn.Search(searchReq)
	if err != nil {
		log.Printf("passwordFound %v", err)
		log.Printf("passwordFound %v", searchReq)
		log.Printf("passwordFound %v", ldapConn)
		log.Printf("passwordFound %v", searchRes)
		return "", err
	}
	if len(searchRes.Entries) == 0 {
		log.Printf("passwordFound %v", err)
		log.Printf("passwordFound %v", searchReq)
		log.Printf("passwordFound %v", ldapConn)
		log.Printf("passwordFound %v", searchRes)
		return "", err
	}
	delReq := ldap.NewDelRequest("uid="+curUser.CN+","+config.InvitationBaseDN, nil)
	ldapConn.Del(delReq)
	return searchRes.Entries[0].GetAttributeValue("seeAlso"), err
}

func HandleUser(w http.ResponseWriter, r *http.Request) {
	templateUser := getTemplate("user.html")
	config := utils.ReadConfig()
	login := checkLogin(w, r)
	if login == nil {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}

	data := &ProfileTplData{
		Login: NestedLoginTplData{
			Status: login,
			Login:  login,
		},
		Common: NestedCommonTplData{
			CanAdmin:     login.Common.CanAdmin,
			LoggedIn:     true,
			ErrorMessage: "",
			Success:      false,
		},
	}

	data.Mail = login.UserEntry.GetAttributeValue("mail")
	data.DisplayName = login.UserEntry.GetAttributeValue("displayName")
	data.GivenName = login.UserEntry.GetAttributeValue("givenName")
	data.Surname = login.UserEntry.GetAttributeValue("sn")
	data.OtherMailbox = login.UserEntry.GetAttributeValue("carLicense")
	data.MailValues = login.UserEntry.GetAttributeValues("mail")
	//	data.Visibility = login.UserEntry.GetAttributeValue(FIELD_NAME_DIRECTORY_VISIBILITY)
	data.Description = login.UserEntry.GetAttributeValue("description")
	//data.ProfilePicture = login.UserEntry.GetAttributeValue(FIELD_NAME_PROFILE_PICTURE)

	if r.Method == "POST" {
		//5MB maximum size files
		r.ParseMultipartForm(5 << 20)
		curUser := user.User{
			DN:           login.Info.DN,
			GivenName:    strings.TrimSpace(strings.Join(r.Form["given_name"], "")),
			DisplayName:  strings.TrimSpace(strings.Join(r.Form["display_name"], "")),
			Mail:         strings.TrimSpace(strings.Join(r.Form["mail"], "")),
			SN:           strings.TrimSpace(strings.Join(r.Form["surname"], "")),
			OtherMailbox: strings.TrimSpace(strings.Join(r.Form["othermailbox"], "")),
			Description:  strings.TrimSpace(strings.Join(r.Form["description"], "")),
			// Password: ,
			//UID: ,
			// CN: ,
		}

		if curUser.DisplayName != "" {
			err := user.Modify(curUser, &config, login.conn)
			if err != nil {
				data.Common.ErrorMessage = "handleUser : " + err.Error()
			} else {
				data.Common.Success = true
			}
		}
		findUser, err := user.Get(curUser, &config, login.conn)
		if err != nil {
			data.Common.ErrorMessage = "handleUser : " + err.Error()
		}
		data.DisplayName = findUser.DisplayName
		data.GivenName = findUser.GivenName
		data.Surname = findUser.SN
		data.Description = findUser.Description
		data.Mail = findUser.Mail
		data.Common.LoggedIn = false

		/*
					visible := strings.TrimSpace(strings.Join(r.Form["visibility"], ""))
					if visible != "" {
						visible = "on"
					} else {
			      visible = "off"
			    }
					data.Visibility = visible
		*/
		/*
					profilePicture, err := uploadProfilePicture(w, r, login)
					if err != nil {
						data.Common.ErrorMessage = err.Error()
					}
			    if profilePicture != "" {
						data.ProfilePicture = profilePicture
					}
		*/

		//modify_request.Replace(FIELD_NAME_DIRECTORY_VISIBILITY, []string{data.Visibility})
		//modify_request.Replace(FIELD_NAME_DIRECTORY_VISIBILITY, []string{"on"})
		//if data.ProfilePicture != "" {
		//		modify_request.Replace(FIELD_NAME_PROFILE_PICTURE, []string{data.ProfilePicture})
		//	}

		// err := login.conn.Modify(modify_request)
		// log.Printf(fmt.Sprintf("Profile:079: %v",modify_request))
		// log.Printf(fmt.Sprintf("Profile:079: %v",err))
		// log.Printf(fmt.Sprintf("Profile:079: %v",data))
		// if err != nil {
		// 	data.Common.ErrorMessage = err.Error()
		// } else {
		// 	data.Common.Success = true
		// }

	}

	// log.Printf("handleUser : %v", data)

	// templateUser.Execute(w, data)
	execTemplate(w, templateUser, data.Common, data.Login, config, data)
}

func HandleUserMail(w http.ResponseWriter, r *http.Request) {

	login := checkLogin(w, r)
	if login == nil {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	email := r.FormValue("email")
	action := r.FormValue("action")
	var err error
	if action == "Add" {
		// Add the new mail value to the entry
		modifyRequest := ldap.NewModifyRequest(login.Info.DN, nil)
		modifyRequest.Add("mail", []string{email})

		err = login.conn.Modify(modifyRequest)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error adding the email: %v", modifyRequest), http.StatusInternalServerError)
			return
		}
	} else if action == "Delete" {
		modifyRequest := ldap.NewModifyRequest(login.Info.DN, nil)
		modifyRequest.Delete("mail", []string{email})

		log.Printf("handleUserMail %v", modifyRequest)
		err = login.conn.Modify(modifyRequest)
		if err != nil {
			log.Printf("handleUserMail DeleteMail %v", err)
			http.Error(w, fmt.Sprintf("Error deleting the email: %s", err), http.StatusInternalServerError)
			return
		}
	}

	message := fmt.Sprintf("Mail value updated successfully to: %s", email)
	http.Redirect(w, r, "/user?message="+message, http.StatusSeeOther)

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

func HandleUserWait(w http.ResponseWriter, r *http.Request) {
	templateUser := getTemplate("user/wait.html")
	templateUser.Execute(w, HomePageData{
		Common: NestedCommonTplData{
			CanAdmin: false,
			LoggedIn: false,
		},
	})
}

func HandleInviteNewAccount(w http.ResponseWriter, r *http.Request) {
	config := utils.ReadConfig()
	l, err := utils.LdapOpen(w)
	if err != nil {
		log.Printf("view-invite.go - HandleInviteNewAccount - ldapOpen : %v", err)
		log.Printf("view-invite.go - HandleInviteNewAccount - ldapOpen: %v", l)
	}
	if l == nil {
		return
	}

	err = l.Bind(config.NewUserDN, config.NewUserPassword)
	if err != nil {
		log.Printf("view-invite.go - HandleInviteNewAccount - l.Bind : %v", err)
		log.Printf("view-invite.go - HandleInviteNewAccount - l.Bind: %v", config.NewUserDN)
		panic(fmt.Sprintf("view-invite.go - HandleInviteNewAccount - l.Bind : %v", err))
	}
	HandleNewAccount(w, r, l, config.NewUserDN)
}

// New account creation using code
func HandleInvitationCode(w http.ResponseWriter, r *http.Request) {
	config := utils.ReadConfig()
	code := mux.Vars(r)["code"]
	code_id, code_pw := readCode(code)
	login := checkLogin(w, r)
	inviteDn := config.InvitationNameAttr + "=" + code_id + "," + config.InvitationBaseDN
	err := login.conn.Bind(inviteDn, code_pw)
	if err != nil {
		templateInviteInvalidCode := getTemplate("user/code/invalid.html")
		templateInviteInvalidCode.Execute(w, nil)
		return
	}
	sReq := ldap.NewSearchRequest(
		inviteDn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(objectclass=*)"),
		[]string{"dn", "creatorsname"},
		nil)
	sr, err := login.conn.Search(sReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(sr.Entries) != 1 {
		http.Error(w, fmt.Sprintf("Expected 1 entry, got %d", len(sr.Entries)), http.StatusInternalServerError)
		return
	}
	invitedBy := sr.Entries[0].GetAttributeValue("creatorsname")
	if HandleNewAccount(w, r, login.conn, invitedBy) {
		del_req := ldap.NewDelRequest(inviteDn, nil)
		err = login.conn.Del(del_req)
		if err != nil {
			log.Printf("Could not delete invitation %s: %s", inviteDn, err)
		}
	}
}

// Common functions for new account
func HandleNewAccount(w http.ResponseWriter, r *http.Request, l *ldap.Conn, invitedBy string) bool {
	config := utils.ReadConfig()
	templateInviteNewAccount := getTemplate("user/new.html")
	data := NewAccountData{
		NewUserDefaultDomain: config.NewUserDefaultDomain,
	}
	if r.Method == "POST" {
		r.ParseForm()
		newUser := user.User{}
		newUser.DisplayName = strings.TrimSpace(strings.Join(r.Form["displayname"], ""))
		newUser.GivenName = strings.TrimSpace(strings.Join(r.Form["givenname"], ""))
		newUser.SN = strings.TrimSpace(strings.Join(r.Form["surname"], ""))
		newUser.OtherMailbox = strings.TrimSpace(strings.Join(r.Form["othermailbox"], ""))
		newUser.Mail = strings.TrimSpace(strings.Join(r.Form["mail"], ""))
		newUser.UID = strings.TrimSpace(strings.Join(r.Form["username"], ""))
		newUser.CN = strings.TrimSpace(strings.Join(r.Form["username"], ""))
		newUser.DN = "cn=" + strings.TrimSpace(strings.Join(r.Form["username"], "")) + "," + config.UserBaseDN
		password1 := strings.Join(r.Form["password"], "")
		password2 := strings.Join(r.Form["password2"], "")
		if password1 != password2 {
			data.Common.Success = false
			data.ErrorPasswordMismatch = true
		} else {
			newUser.Password = password2
			l.Bind(config.NewUserDN, config.NewUserPassword)
			err := Add(newUser, &config, l)
			if err != nil {
				data.Common.Success = false
				data.Common.ErrorMessage = err.Error()
			}
			http.Redirect(w, r, "/user/wait", http.StatusFound)
		}
		// tryCreateAccount(l, data, password1, password2, invitedBy)
	} else {
		data.SuggestPW = fmt.Sprintf("%s", utils.SuggestPassword())
	}
	data.Common.CanAdmin = false
	data.Common.LoggedIn = false

	templateInviteNewAccount.Execute(w, data)
	return data.Common.Success
}

func TryCreateAccount(l *ldap.Conn, data *NewAccountData, pass1 string, pass2 string, invitedBy string) {
	config := utils.ReadConfig()
	checkFailed := false
	// Check if username is correct
	if match, err := regexp.MatchString("^[a-z0-9._-]+$", data.Username); !(err == nil && match) {
		data.ErrorInvalidUsername = true
		checkFailed = true
	}
	// Check if user exists
	userDn := config.UserNameAttr + "=" + data.Username + "," + config.UserBaseDN
	searchRq := ldap.NewSearchRequest(
		userDn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectclass=*)",
		[]string{"dn"},
		nil)
	sr, err := l.Search(searchRq)
	if err != nil {
		data.Common.ErrorMessage = err.Error()
		checkFailed = true
	}
	if len(sr.Entries) > 0 {
		data.ErrorUsernameTaken = true
		checkFailed = true
	}
	// Check that password is long enough
	if len(pass1) < 8 {
		data.ErrorPasswordTooShort = true
		checkFailed = true
	}
	if pass1 != pass2 {
		data.ErrorPasswordMismatch = true
		checkFailed = true
	}
	if checkFailed {
		return
	}
	// Actually create user
	req := ldap.NewAddRequest(userDn, nil)
	req.Attribute("objectclass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
	req.Attribute("structuralobjectclass", []string{"inetOrgPerson"})
	pw, err := utils.SSHAEncode(pass1)
	if err != nil {
		data.Common.ErrorMessage = err.Error()
		return
	}
	req.Attribute("userpassword", []string{pw})
	req.Attribute("invitedby", []string{invitedBy})
	if len(data.DisplayName) > 0 {
		req.Attribute("displayname", []string{data.DisplayName})
	}
	if len(data.GivenName) > 0 {
		req.Attribute("givenname", []string{data.GivenName})
	}
	if len(data.Surname) > 0 {
		req.Attribute("sn", []string{data.Surname})
	}
	if len(config.InvitedMailFormat) > 0 {
		email := strings.ReplaceAll(config.InvitedMailFormat, "{}", data.Username)
		req.Attribute("mail", []string{email})
	}
	err = l.Add(req)
	if err != nil {
		data.Common.ErrorMessage = err.Error()
		return
	}
	for _, group := range config.InvitedAutoGroups {
		req := ldap.NewModifyRequest(group, nil)
		req.Add("member", []string{userDn})
		err = l.Modify(req)
		if err != nil {
			data.Common.WarningMessage += fmt.Sprintf("Cannot add to %s: %s\n", group, err.Error())
		}
	}
	data.Common.Success = true
}

// ---- Code generation ----
func HandleInviteSendCode(w http.ResponseWriter, r *http.Request) {
	config := utils.ReadConfig()
	templateInviteSendCode := getTemplate("user/code/send.html")
	login := checkInviterLogin(w, r)
	if login == nil {
		return
	}
	if r.Method == "POST" {
		r.ParseForm()
		data := &SendCodeData{
			WebBaseAddress: config.WebAddress,
		}
		// modify_request := ldap.NewModifyRequest(login.UserEntry.DN, nil)
		// // choice := strings.Join(r.Form["choice"], "")
		// // sendto := strings.Join(r.Form["sendto"], "")
		code, code_id, code_pw := genCode()
		log.Printf("272: %v %v %v", code, code_id, code_pw)
		// // Create invitation object in database
		// modify_request.Add("carLicense", []string{fmt.Sprintf("%s,%s,%s",code, code_id, code_pw)})
		// err := login.conn.Modify(modify_request)
		// if err != nil {
		// 	data.Common.ErrorMessage = err.Error()
		// 	// return
		// } else {
		// 	data.Common.Success = true
		// 	data.CodeDisplay = code
		// }
		log.Printf("279: %v %v %v", code, code_id, code_pw)
		addReq := ldap.NewAddRequest("documentIdentifier="+code_id+","+config.InvitationBaseDN, nil)
		addReq.Attribute("objectClass", []string{"top", "document", "simpleSecurityObject"})
		addReq.Attribute("cn", []string{code})
		addReq.Attribute("userPassword", []string{code_pw})
		addReq.Attribute("documentIdentifier", []string{code_id})
		log.Printf("285: %v %v %v", code, code_id, code_pw)
		log.Printf("286: %v", addReq)
		err := login.conn.Add(addReq)
		if err != nil {
			data.Common.ErrorMessage = err.Error()
			// return
		} else {
			data.Common.Success = true
			data.CodeDisplay = code
		}
		data.Common.CanAdmin = login.Common.CanAdmin
		templateInviteSendCode.Execute(w, data)
		// if choice == "display" || choice == "send" {
		// 	log.Printf("260: %v %v %v %v", login, choice, sendto, data)
		// 	trySendCode(login, choice, sendto, data)
		// }
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

func HandleLostPassword(w http.ResponseWriter, r *http.Request) {
	config := utils.ReadConfig()
	templateLostPasswordPage := getTemplate("passwd/lost.html")
	if checkLogin(w, r) != nil {
		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
	}

	data := PasswordLostData{
		Common: NestedCommonTplData{
			CanAdmin: false,
			LoggedIn: false},
	}

	if r.Method == "POST" {
		r.ParseForm()
		data.Username = strings.TrimSpace(strings.Join(r.Form["username"], ""))
		data.Mail = strings.TrimSpace(strings.Join(r.Form["mail"], ""))
		data.OtherMailbox = strings.TrimSpace(strings.Join(r.Form["othermailbox"], ""))
		curUser := user.User{
			CN:           strings.TrimSpace(strings.Join(r.Form["username"], "")),
			UID:          strings.TrimSpace(strings.Join(r.Form["username"], "")),
			Mail:         strings.TrimSpace(strings.Join(r.Form["mail"], "")),
			OtherMailbox: strings.TrimSpace(strings.Join(r.Form["othermailbox"], "")),
		}
		ldapNewConn, err := OpenNewUserLdap(&config)
		if err != nil {
			log.Printf(fmt.Sprintf("handleLostPassword 99 : %v %v", err, ldapNewConn))
			data.Common.ErrorMessage = err.Error()
		}
		if err != nil {
			log.Printf(fmt.Sprintf("handleLostPassword 104 : %v %v", err, ldapNewConn))
			data.Common.ErrorMessage = err.Error()
		} else {
			// err = ldapConn.Bind(config.NewUserDN, config.NewUserPassword)
			if err != nil {
				log.Printf(fmt.Sprintf("handleLostPassword 109 : %v %v", err, ldapNewConn))
				data.Common.ErrorMessage = err.Error()
			} else {
				data.Common.Success = true
			}
		}
		err = PasswordLost(curUser, &config, ldapNewConn)
	}
	data.Common.CanAdmin = false
	// templateLostPasswordPage.Execute(w, data)
	execTemplate(w, templateLostPasswordPage, data.Common, NestedLoginTplData{}, config, data)
}

func HandleFoundPassword(w http.ResponseWriter, r *http.Request) {
	config := utils.ReadConfig()
	templateFoundPasswordPage := getTemplate("passwd.html")
	data := PasswdTplData{
		Common: NestedCommonTplData{
			CanAdmin: false,
			LoggedIn: false},
	}
	code := mux.Vars(r)["code"]
	// code = strings.TrimSpace(strings.Join([]string{code}, ""))
	newCode, _ := b64.URLEncoding.DecodeString(code)
	ldapNewConn, err := OpenNewUserLdap(&config)
	if err != nil {
		log.Printf("handleFoundPassword openNewUserLdap(config) : %v", err)
		data.Common.ErrorMessage = err.Error()
	}
	codeArray := strings.Split(string(newCode), ";")
	curUser := user.User{
		UID:      codeArray[0],
		Password: codeArray[1],
		DN:       "uid=" + codeArray[0] + "," + config.InvitationBaseDN,
	}
	curUser.SeeAlso, err = PasswordFound(curUser, &config, ldapNewConn)
	if err != nil {
		log.Printf("passwordFound(user, config, ldapConn) %v", err)
		log.Printf("passwordFound(user, config, ldapConn) %v", curUser)
		log.Printf("passwordFound(user, config, ldapConn) %v", ldapNewConn)
		data.Common.ErrorMessage = err.Error()
	}
	if r.Method == "POST" {
		r.ParseForm()

		password := strings.Join(r.Form["password"], "")
		password2 := strings.Join(r.Form["password2"], "")

		if len(password) < 8 {
			data.TooShortError = true
		} else if password2 != password {
			data.NoMatchError = true
		} else {
			err := Passwd(user.User{
				DN:       curUser.SeeAlso,
				Password: password,
			}, &config, ldapNewConn)
			if err != nil {
				data.Common.ErrorMessage = err.Error()
			} else {
				data.Common.Success = true
			}
		}
	}
	data.Common.CanAdmin = false
	// templateFoundPasswordPage.Execute(w, data)
	execTemplate(w, templateFoundPasswordPage, data.Common, data.Login, config, data)
}

func HandlePasswd(w http.ResponseWriter, r *http.Request) {
	config := utils.ReadConfig()
	templatePasswd := getTemplate("passwd.html")
	data := &PasswdTplData{
		Common: NestedCommonTplData{
			CanAdmin:     false,
			LoggedIn:     true,
			ErrorMessage: "",
			Success:      false,
		},
	}

	login := checkLogin(w, r)
	if login == nil {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	data.Login.Status = login
	data.Common.CanAdmin = login.Common.CanAdmin

	if r.Method == "POST" {
		r.ParseForm()

		password := strings.Join(r.Form["password"], "")
		password2 := strings.Join(r.Form["password2"], "")

		if len(password) < 8 {
			data.TooShortError = true
		} else if password2 != password {
			data.NoMatchError = true
		} else {
			err := Passwd(user.User{
				DN:       login.Info.DN,
				Password: password,
			}, &config, login.conn)
			if err != nil {
				data.Common.ErrorMessage = err.Error()
			} else {
				data.Common.Success = true
			}
		}
	}
	data.Common.CanAdmin = false
	// templatePasswd.Execute(w, data)
	execTemplate(w, templatePasswd, data.Common, data.Login, config, data)
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

func (d EntryList) Len() int {
	return len(d)
}

func (d EntryList) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d EntryList) Less(i, j int) bool {
	return d[i].DN < d[j].DN
}

func trySendCode(login *LoginStatus, choice string, sendto string, data *SendCodeData) {
	config := utils.ReadConfig()
	log.Printf("269: %v %v %v %v", login, choice, sendto, data)
	// Generate code
	code, code_id, code_pw := genCode()
	log.Printf("272: %v %v %v", code, code_id, code_pw)
	// Create invitation object in database
	// len_base_dn := len(strings.Split(config.BaseDN, ","))
	// dn_split := strings.Split(super_dn, ",")
	// for i := len_base_dn + 1; i <= len(dn_split); i++ {
	// 	path = append(path, PathItem{
	// 		DN:         strings.Join(dn_split[len(dn_split)-i:len(dn_split)], ","),
	// 		Identifier: dn_split[len(dn_split)-i],
	// 	})
	// }
	// data := &SendCodeData{
	// 	WebBaseAddress: config.WebAddress,
	// }
	// // Handle data
	// data := &CreateData{
	// 	SuperDN: super_dn,
	// 	Path:    path,
	// }
	// data.IdType = config.UserNameAttr
	// data.StructuralObjectClass = "inetOrgPerson"
	// data.ObjectClass = "inetOrgPerson\norganizationalPerson\nperson\ntop"
	// data.IdValue = strings.TrimSpace(strings.Join(r.Form["idvalue"], ""))
	// data.DisplayName = strings.TrimSpace(strings.Join(r.Form["displayname"], ""))
	// data.GivenName = strings.TrimSpace(strings.Join(r.Form["givenname"], ""))
	// data.Mail = strings.TrimSpace(strings.Join(r.Form["mail"], ""))
	// data.Member = strings.TrimSpace(strings.Join(r.Form["member"], ""))
	// data.Description = strings.TrimSpace(strings.Join(r.Form["description"], ""))
	// data.SN = strings.TrimSpace(strings.Join(r.Form["sn"], ""))
	// object_class := []string{}
	// for _, oc := range strings.Split(data.ObjectClass, "\n") {
	// 	x := strings.TrimSpace(oc)
	// 	if x != "" {
	// 		object_class = append(object_class, x)
	// 	}
	// }
	// dn := data.IdType + "=" + data.IdValue + "," + super_dn
	// 		req := ldap.NewAddRequest(dn, nil)
	// 		req.Attribute("objectclass", object_class)
	// 		// req.Attribute("mail", []string{data.IdValue})
	//     /*
	// 		if data.StructuralObjectClass != "" {
	// 			req.Attribute("structuralobjectclass", []string{data.StructuralObjectClass})
	// 		}
	//     */
	// 		if data.DisplayName != "" {
	// 			req.Attribute("displayname", []string{data.DisplayName})
	// 		}
	// 		if data.GivenName != "" {
	// 			req.Attribute("givenname", []string{data.GivenName})
	// 		}
	// 		if data.Mail != "" {
	// 			req.Attribute("mail", []string{data.Mail})
	// 		}
	// 		if data.Member != "" {
	// 			req.Attribute("member", []string{data.Member})
	// 		}
	// 		if data.SN != "" {
	// 			req.Attribute("sn", []string{data.SN})
	// 		}
	// 		if data.Description != "" {
	// 			req.Attribute("description", []string{data.Description})
	// 		}
	// 		err := login.conn.Add(req)
	//     // log.Printf("899: %v",err)
	//     // log.Printf("899: %v",req)
	//     // log.Printf("899: %v",data)
	// 		if err != nil {
	// 			data.Common.Error = err.Error()
	// 		} else {
	// 			if template == "ml" {
	// 				http.Redirect(w, r, "/admin/mailing/"+data.IdValue, http.StatusFound)
	// 			} else {
	// 				http.Redirect(w, r, "/admin/ldap/"+dn, http.StatusFound)
	// 			}
	// 		}
	// inviteDn := config.InvitationNameAttr + "=" + code_id + "," + config.InvitationBaseDN
	// req := ldap.NewAddRequest(inviteDn, nil)
	// pw, err := SSHAEncode(code_pw)
	// if err != nil {
	// 	data.Common.ErrorMessage = err.Error()
	// 	return
	// }
	// req.Attribute("employeeNumber", []string{pw})
	// req.Attribute("objectclass", []string{"top", "invitationCode"})
	// err = login.conn.Add(req)
	// if err != nil {
	// 	log.Printf("286: %v", req)
	// 	data.Common.ErrorMessage = err.Error()
	// 	return
	// }

	// If we want to display it, do so
	if choice == "display" {
		data.Common.Success = true
		data.CodeDisplay = code
		return
	}
	// Otherwise, we are sending a mail
	if !EMAIL_REGEXP.MatchString(sendto) {
		data.ErrorInvalidEmail = true
		return
	}
	templateMail := template.Must(template.ParseFiles(templatePath + "/invite_mail.txt"))
	buf := bytes.NewBuffer([]byte{})
	templateMail.Execute(buf, &CodeMailFields{
		To:             sendto,
		From:           config.MailFrom,
		InviteFrom:     login.WelcomeName(),
		Code:           code,
		WebBaseAddress: config.WebAddress,
	})
	log.Printf("Sending mail to: %s", sendto)
	// var auth sasl.Client = nil
	// if config.SMTPUsername != "" {
	// 	auth = sasl.NewPlainClient("", config.SMTPUsername, config.SMTPPassword)
	// }
	// err = smtp.SendMail(config.SMTPServer, auth, config.MailFrom, []string{sendto}, buf)
	// if err != nil {
	// 	data.Common.ErrorMessage = err.Error()
	// 	return
	// }
	// log.Printf("Mail sent.")
	data.Common.Success = true
	data.CodeSentTo = sendto
}

func genCode() (code string, code_id string, code_pw string) {
	random := make([]byte, 32)
	n, err := rand.Read(random)
	if err != nil || n != 32 {
		log.Fatalf("Could not generate random bytes: %s", err)
	}
	a := binary.BigEndian.Uint32(random[0:4])
	b := binary.BigEndian.Uint32(random[4:8])
	c := binary.BigEndian.Uint32(random[8:12])
	code = fmt.Sprintf("%03d-%03d-%03d", a%1000, b%1000, c%1000)
	code_id, code_pw = readCode(code)
	log.Printf("342: %v %v %v", code, code_id, code_pw)
	return code, code_id, code_pw
}

func readCode(code string) (code_id string, code_pw string) {
	// Strip everything that is not a digit
	code_digits := ""
	for _, c := range code {
		if c >= '0' && c <= '9' {
			code_digits = code_digits + string(c)
		}
	}
	id_hash := argon2.IDKey([]byte(code_digits), []byte("Guichet ID"), 2, 64*1024, 4, 32)
	pw_hash := argon2.IDKey([]byte(code_digits), []byte("Guichet PW"), 2, 64*1024, 4, 32)
	code_id = hex.EncodeToString(id_hash[:8])
	code_pw = hex.EncodeToString(pw_hash[:16])
	return code_id, code_pw
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

func execTemplate(w http.ResponseWriter, t *template.Template, commonData NestedCommonTplData, loginData NestedLoginTplData, config utils.ConfigFile, data any) error {
	commonData.WebsiteURL = config.WebAddress
	commonData.WebsiteName = config.Org
	// log.Printf("execTemplate: %v", loginData)
	return t.Execute(w, LayoutTemplateData{
		Common: commonData,
		Login:  loginData,
		Data:   data,
	})
}

func getTemplate(name string) *template.Template {
	return template.Must(template.New("layout.html").Funcs(template.FuncMap{
		"contains": strings.Contains,
	}).ParseFiles(
		templatePath+"/layout.html",
		templatePath+"/"+name,
	))
}

func (login *LoginStatus) WelcomeName() string {
	ret := login.UserEntry.GetAttributeValue("givenName")
	if ret == "" {
		ret = login.UserEntry.GetAttributeValue("displayName")
	}
	if ret == "" {
		ret = login.Info.Username
	}
	return ret
}

type EntryList []*ldap.Entry

type PasswordFoundData struct {
	Common       NestedCommonTplData
	Login        NestedLoginTplData
	Username     string
	Mail         string
	OtherMailbox string
}
type PasswordLostData struct {
	Common       NestedCommonTplData
	ErrorMessage string
	Success      bool
	Username     string
	Mail         string
	OtherMailbox string
}
type NewAccountData struct {
	Username     string
	DisplayName  string
	GivenName    string
	Surname      string
	Mail         string
	SuggestPW    string
	OtherMailbox string

	ErrorUsernameTaken    bool
	ErrorInvalidUsername  bool
	ErrorPasswordTooShort bool
	ErrorPasswordMismatch bool
	Common                NestedCommonTplData
	NewUserDefaultDomain  string
}
type SendCodeData struct {
	Common            NestedCommonTplData
	ErrorInvalidEmail bool

	CodeDisplay    string
	CodeSentTo     string
	WebBaseAddress string
}

//ProfilePicture string
//Visibility     string

type PasswdTplData struct {
	Common        NestedCommonTplData
	Login         NestedLoginTplData
	TooShortError bool
	NoMatchError  bool
}

type LayoutTemplateData struct {
	Common NestedCommonTplData
	Login  NestedLoginTplData
	Data   any
}

type LoginInfo struct {
	Username string
	DN       string
	Password string
}
type LoginStatus struct {
	Info      *LoginInfo
	conn      *ldap.Conn
	UserEntry *ldap.Entry
	Common    NestedCommonTplData
}
type NestedCommonTplData struct {
	Error          string
	ErrorMessage   string
	CanAdmin       bool
	CanInvite      bool
	LoggedIn       bool
	Success        bool
	WarningMessage string
	WebsiteName    string
	WebsiteURL     string
}
type NestedLoginTplData struct {
	Login    *LoginStatus
	Username string
	Status   *LoginStatus
}
type ProfileTplData struct {
	Mail         string
	MailValues   []string
	DisplayName  string
	GivenName    string
	Surname      string
	Description  string
	OtherMailbox string
	Common       NestedCommonTplData
	Login        NestedLoginTplData
}

type HomePageData struct {
	Common NestedCommonTplData
	Login  NestedLoginTplData
	BaseDN string
	Org    string
}

type LoginFormData struct {
	Username  string
	WrongUser bool
	WrongPass bool
	Common    NestedCommonTplData
}
type CodeMailFields struct {
	From           string
	To             string
	Code           string
	InviteFrom     string
	WebBaseAddress string
	Common         NestedCommonTplData
}
type AdminUsersTplData struct {
	UserNameAttr string
	UserBaseDN   string
	Users        EntryList
	Common       NestedCommonTplData
	Login        NestedLoginTplData
}
type AdminLDAPTplData struct {
	DN string

	Path          []PathItem
	ChildrenOU    []Child
	ChildrenOther []Child
	CanAddChild   bool
	Props         map[string]*PropValues
	CanDelete     bool

	HasMembers         bool
	Members            []EntryName
	PossibleNewMembers []EntryName
	HasGroups          bool
	Groups             []EntryName
	PossibleNewGroups  []EntryName

	ListMemGro map[string]string

	Common NestedCommonTplData
	Login  NestedLoginTplData
}
type AdminMailingListTplData struct {
	Common             NestedCommonTplData
	Login              NestedLoginTplData
	MailingNameAttr    string
	MailingBaseDN      string
	MailingList        *ldap.Entry
	Members            EntryList
	PossibleNewMembers EntryList
	AllowGuest         bool
}
type AdminMailingTplData struct {
	Common          NestedCommonTplData
	Login           NestedLoginTplData
	MailingNameAttr string
	MailingBaseDN   string
	MailingLists    EntryList
}
type AdminGroupsTplData struct {
	Common        NestedCommonTplData
	Login         NestedLoginTplData
	GroupNameAttr string
	GroupBaseDN   string
	Groups        EntryList
}
type EntryName struct {
	DN   string
	Name string
}
type Child struct {
	DN         string
	Identifier string
	Name       string
}
type PathItem struct {
	DN         string
	Identifier string
	Active     bool
}
type PropValues struct {
	Name      string
	Values    []string
	Editable  bool
	Deletable bool
}
type CreateData struct {
	SuperDN  string
	Path     []PathItem
	Template string

	IdType                string
	IdValue               string
	DisplayName           string
	GivenName             string
	Member                string
	Mail                  string
	Description           string
	StructuralObjectClass string
	ObjectClass           string
	SN                    string
	OtherMailbox          string

	Common NestedCommonTplData
	Login  NestedLoginTplData
}
type SearchResult struct {
	DN             string
	Id             string
	DisplayName    string
	Email          string
	Description    string
	ProfilePicture string
}
type SearchResults struct {
	Results []SearchResult
}
