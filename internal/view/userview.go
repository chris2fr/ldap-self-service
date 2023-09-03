package view

import (
	"fmt"
	"ldap-self-service/internal/user"
	"ldap-self-service/internal/utils"
	"log"
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

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

func HandleUserWait(w http.ResponseWriter, r *http.Request) {
	templateUser := getTemplate("user/wait.html")
	templateUser.Execute(w, HomePageData{
		Common: NestedCommonTplData{
			CanAdmin: false,
			LoggedIn: false,
		},
	})
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
