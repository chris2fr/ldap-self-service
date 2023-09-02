package user

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"ldap-self-service/internal/utils"
	"log"
	"strings"
)

// Modify User
func Modify(user User, config *utils.ConfigFile, ldapConn *ldap.Conn) error {
	modify_request := ldap.NewModifyRequest(user.DN, nil)
	previousUser, err := Get(user, config, ldapConn)
	if err != nil {
		return err
	}
	replaceIfContent(modify_request, "displayName", user.DisplayName, previousUser.DisplayName)
	replaceIfContent(modify_request, "givenName", user.GivenName, previousUser.GivenName)
	replaceIfContent(modify_request, "sn", user.SN, previousUser.SN)
	replaceIfContent(modify_request, "carLicense", user.OtherMailbox, user.OtherMailbox)
	replaceIfContent(modify_request, "description", user.Description, previousUser.Description)
	err = ldapConn.Modify(modify_request)
	if err != nil {
		log.Printf(fmt.Sprintf("71: %v", err))
		log.Printf(fmt.Sprintf("72: %v", modify_request))
		log.Printf(fmt.Sprintf("73: %v", user))
		return err
	}
	return nil
}

// Get user
func Get(user User, config *utils.ConfigFile, ldapConn *ldap.Conn) (*User, error) {
	searchReq := ldap.NewSearchRequest(
		user.DN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"cn",
			"givenName",
			"displayName",
			"uid",
			"sn",
			"mail",
			"description",
			"carLicense",
		},
		nil)
	searchRes, err := ldapConn.Search(searchReq)
	if err != nil {
		log.Printf("get User : %v", err)
		log.Printf("get User : %v", searchReq)
		log.Printf("get User : %v", searchRes)
		return nil, err
	}
	userEntry := searchRes.Entries[0]
	resUser := User{
		DN:           user.DN,
		GivenName:    searchRes.Entries[0].GetAttributeValue("givenName"),
		DisplayName:  searchRes.Entries[0].GetAttributeValue("displayName"),
		Description:  searchRes.Entries[0].GetAttributeValue("description"),
		SN:           searchRes.Entries[0].GetAttributeValue("sn"),
		UID:          searchRes.Entries[0].GetAttributeValue("uid"),
		CN:           searchRes.Entries[0].GetAttributeValue("cn"),
		Mail:         searchRes.Entries[0].GetAttributeValue("mail"),
		OtherMailbox: searchRes.Entries[0].GetAttributeValue("carLicense"),
		CanAdmin:     strings.EqualFold(user.DN, config.AdminAccount),
		CanInvite:    true,
		UserEntry:    userEntry,
	}
	searchReq.BaseDN = config.GroupCanAdmin
	searchReq.Filter = "(member=" + user.DN + ")"
	searchRes, err = ldapConn.Search(searchReq)
	if err == nil {
		if len(searchRes.Entries) > 0 {
			resUser.CanAdmin = true
		}
	}
	return &resUser, nil
}

func replaceIfContent(modifReq *ldap.ModifyRequest, key string, value string, previousValue string) error {
	if value != "" {
		modifReq.Replace(key, []string{value})
	} else if previousValue != "" {
		modifReq.Delete(key, []string{previousValue})
	}
	return nil
}

func Bind(user User, config *utils.ConfigFile, ldapConn *ldap.Conn) error {
	return ldapConn.Bind(user.DN, user.Password)
}

/*
Represents a user
*/
type User struct {
	DN           string
	CN           string
	GivenName    string
	DisplayName  string
	Mail         string
	SN           string
	UID          string
	Description  string
	Password     string
	OtherMailbox string
	CanAdmin     bool
	CanInvite    bool
	UserEntry    *ldap.Entry
	SeeAlso      string
}

type EntryList []*ldap.Entry
