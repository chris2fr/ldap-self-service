package view

import (
	"regexp"

	"ldap-self-service/internal/utils"
	"net/http"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
)

// For the template engine
var templatePath = "../templates"

// Configure for github.com/gorilla/sessions

var EMAIL_REGEXP = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

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

func (d EntryList) Len() int {
	return len(d)
}

func (d EntryList) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d EntryList) Less(i, j int) bool {
	return d[i].DN < d[j].DN
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
