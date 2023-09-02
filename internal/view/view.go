package view

import (
	"crypto/rand"

	"fmt"

	"ldap-self-service/internal/user"
	"ldap-self-service/internal/utils"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/sessions"
)

// For the template engine
var templatePath = "../templates"

// For sessions
var store sessions.Store = nil

// Configure for github.com/gorilla/sessions

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
	log.Printf("Do Login %v %v", user_dn, username)
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
		// log.Printf("%v", "Parsing Form handleLogin")
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
	log.Printf("Logout %v", "guichet_session")
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

	log.Printf("handleUser : %v", data)

	// templateUser.Execute(w, data)
	execTemplate(w, templateUser, data.Common, data.Login, config, data)
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
	log.Printf("execTemplate: %v", loginData)
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
