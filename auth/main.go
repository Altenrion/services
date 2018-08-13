package main

import (
	au "github.com/altenrion/pkgs/auth"
	aup "github.com/altenrion/pkgs/auth/providers"
	"net/http"
	"log"
	"fmt"
	"encoding/json"
)


// todo: must be set by EnvVars
const ServicePort = "999"
const ServiceHost = "dcsp.vtb.ru"


func TokenSearcher(credentials au.Credentials) (string, error){
	//todo: finish logick here

	return "", nil
}

//todo: need to start tcp LDAP server or @mock it
func main() {
	http.HandleFunc("/authorise", Authorize)
	log.Fatal(http.ListenAndServe(":"+ServicePort, nil))
}

func Authorize(w http.ResponseWriter, r *http.Request)  {

	credentials, extractErr := extractCredentials(r)
	if extractErr != nil {
		http.Error(w, fmt.Sprintf("Authorisation failed : bad credentials : [%s]", extractErr.Error()), 400)
	}

	//todo: make this config dynamic, store in database or env| Devops vars
	authService := au.AuthorisationService{
		Identity: aup.LdapProvider{
			Config:aup.LdapConfig{
				UserCredentials : credentials,

				//todo: make this section correct & dynamic| maybe env vars

				LdapServer : "ad.example.com:389",
				LdapBind : "search@example.com",
				LdapPassword : "Password123!",

				FilterDN : "(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=CN=Chat,CN=Users,DC=example,DC=com)(|(sAMAccountName={username})(mail={username})))",
				BaseDN : "CN=Users,DC=example,DC=com",
			},
		},
		Token: aup.JWTProvider{
			UserCredentials:    credentials,

			//todo: make this env vars
			JWTExpirationDelta: 20,
			JWTSecretKey:       "SomeCoolSecretKey",
			UserTokensSearcher: TokenSearcher,
		},
	}

	_, authErr := authService.Authorize()
	if authErr != nil {
		http.Error(w, fmt.Sprintf("Authorisation failed : can not authorize : [%s]", authErr.Error()), 400)
	}

	token, err := authService.Tokenize()
	if err != nil {
		http.Error(w, fmt.Sprintf("Authorisation failed : can not get token : [%s]", err.Error()), 400)
	}

	response := "{\"Token\":"+token+"\"}"

	// todo: Set Token to Cookies ?
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Token", token)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func extractCredentials(r *http.Request) (au.Credentials, error ){
	var credentials au.Credentials

	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&credentials)
	if err != nil {
		return au.Credentials{}, err
	}

	return credentials, nil
}
