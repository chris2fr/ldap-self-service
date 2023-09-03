package view

import (
	"bytes"

	b64 "encoding/base64"
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
)

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
