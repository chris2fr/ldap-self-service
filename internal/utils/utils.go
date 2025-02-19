package utils

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/go-ldap/ldap/v3"
	"github.com/jsimonetti/pwscheme/ssha512"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
)

// For readConfig
var ConfigFlag = flag.String("config", "../conf/config.json", "Configuration file path")
var config *ConfigFile

// Read the application config file
func ReadConfig() ConfigFile {
	// Default configuration values for certain fields
	config_file := ConfigFile{
		HttpBindAddr:   ":9991",
		LdapServerAddr: "ldap://127.0.0.1:389",

		UserNameAttr:  "uid",
		GroupNameAttr: "gid",

		InvitationNameAttr: "cn",
		InvitedAutoGroups:  []string{},

		Org: "ResDigita",
	}

	_, err := os.Stat(*ConfigFlag)
	if os.IsNotExist(err) {
		log.Fatalf("Could not find Guichet configuration file at %s. Please create this file, for exemple starting with config.json.exemple and customizing it for your deployment.", *ConfigFlag)
	}

	if err != nil {
		log.Fatal(err)
	}

	bytes, err := ioutil.ReadFile(*ConfigFlag)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(bytes, &config_file)
	if err != nil {
		log.Fatal(err)
	}

	return config_file
}

func OpenLdap(config *ConfigFile) (*ldap.Conn, error) {
	var ldapConn *ldap.Conn
	var err error
	if config.LdapTLS {
		tlsConf := &tls.Config{
			ServerName:         config.LdapServerAddr,
			InsecureSkipVerify: true,
		}
		ldapConn, err = ldap.DialTLS("tcp", net.JoinHostPort(config.LdapServerAddr, "636"), tlsConf)
	} else {
		ldapConn, err = ldap.DialURL("ldap://" + config.LdapServerAddr)
	}
	if err != nil {
		log.Printf("openLDAP %v", err)
		log.Printf("openLDAP %v", config.LdapServerAddr)
	}
	return ldapConn, err

	// l, err := ldap.DialURL(config.LdapServerAddr)
	// if err != nil {
	// 	log.Printf(fmt.Sprint("Erreur connect LDAP %v", err))
	// 	log.Printf(fmt.Sprint("Erreur connect LDAP %v", config.LdapServerAddr))
	// 	return nil
	// } else {
	// 	return l
	// }
}

func LdapOpen(w http.ResponseWriter) (*ldap.Conn, error) {
	config := ReadConfig()
	if config.LdapTLS {
		tlsConf := &tls.Config{
			ServerName:         config.LdapServerAddr,
			InsecureSkipVerify: true,
		}
		return ldap.DialTLS("tcp", net.JoinHostPort(config.LdapServerAddr, "636"), tlsConf)
	} else {
		return ldap.DialURL(config.LdapServerAddr)
	}

	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	log.Printf(fmt.Sprintf("27: %v %v", err, l))
	// 	return nil
	// }

	// return l
}

// Suggesting a 12 char password with some excentrics
func SuggestPassword() string {
	password := ""
	chars := "abcdfghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*+_-="
	for i := 0; i < 12; i++ {
		password += string([]rune(chars)[rand.Intn(len(chars))])
	}
	return password
}

// Encode encodes the []byte of raw password
func SSHAEncode(rawPassPhrase string) (string, error) {
	return ssha512.Generate(rawPassPhrase, 16)
}

type ConfigFile struct {
	HttpBindAddr   string `json:"http_bind_addr"`
	LdapServerAddr string `json:"ldap_server_addr"`
	LdapTLS        bool   `json:"ldap_tls"`

	BaseDN        string `json:"base_dn"`
	UserBaseDN    string `json:"user_base_dn"`
	UserNameAttr  string `json:"user_name_attr"`
	GroupBaseDN   string `json:"group_base_dn"`
	GroupNameAttr string `json:"group_name_attr"`

	MailingBaseDN       string `json:"mailing_list_base_dn"`
	MailingNameAttr     string `json:"mailing_list_name_attr"`
	MailingGuestsBaseDN string `json:"mailing_list_guest_user_base_dn"`

	InvitationBaseDN   string   `json:"invitation_base_dn"`
	InvitationNameAttr string   `json:"invitation_name_attr"`
	InvitedMailFormat  string   `json:"invited_mail_format"`
	InvitedAutoGroups  []string `json:"invited_auto_groups"`

	WebAddress   string `json:"web_address"`
	MailFrom     string `json:"mail_from"`
	SMTPServer   string `json:"smtp_server"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`

	AdminAccount   string `json:"admin_account"`
	GroupCanInvite string `json:"group_can_invite"`
	GroupCanAdmin  string `json:"group_can_admin"`

	S3AdminEndpoint string `json:"s3_admin_endpoint"`
	S3AdminToken    string `json:"s3_admin_token"`

	S3Endpoint  string `json:"s3_endpoint"`
	S3AccessKey string `json:"s3_access_key"`
	S3SecretKey string `json:"s3_secret_key"`
	S3Region    string `json:"s3_region"`
	S3Bucket    string `json:"s3_bucket"`

	Org                  string `json:"org"`
	DomainName           string `json:"domain_name"`
	NewUserDN            string `json:"new_user_dn"`
	NewUserPassword      string `json:"new_user_password"`
	NewUsersBaseDN       string `json:"new_users_base_dn"`
	NewUserDefaultDomain string `json:"new_user_default_domain"`
}
