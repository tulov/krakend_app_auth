package krakend_flora_app_auth

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/martian"
	"github.com/google/martian/parse"
	"github.com/google/martian/v3/log"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	parse.Register("auth.FloraApplications", marvelModifierFromJSON)
}

type AuthData struct {
	Id   uint8  `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// MarvelModifier contains the private and public Marvel API key
type AuthModifier struct {
	applications map[uint8]AuthData
}

// MarvelModifierJSON to Unmarshal the JSON configuration
type MarvelModifierJSON struct {
	Applications []AuthData           `json:"applications"`
	Scope        []parse.ModifierType `json:"scope"`
}

// ModifyRequest modifies the query string of the request with the given key and value.
func (m *AuthModifier) ModifyRequest(req *http.Request) error {
	authorizationHeader := req.Header.Get("Authorization")
	if authorizationHeader == "" {
		return fmt.Errorf("didn't set authorization header")
	}
	authHeaderData := strings.TrimPrefix(authorizationHeader, "Bearer ")
	if authHeaderData == "" {
		return fmt.Errorf("not correct authorization header")
	}

	res, err := hex.DecodeString(authHeaderData)
	if err != nil {
		return fmt.Errorf("can't decode authorization header")
	}
	splitRes := strings.SplitN(string(res), ":", 1)
	if len(splitRes) != 2 {
		return fmt.Errorf("not correct auth data")
	}
	appId, err := strconv.ParseUint(splitRes[0], 10, 8)
	if err != nil {
		return fmt.Errorf("not correct app id")
	}
	app, ok := m.applications[uint8(appId)]
	if !ok {
		return fmt.Errorf("access denied")
	}

	appKey := splitRes[1]
	if app.Key != appKey {
		return fmt.Errorf("access denied")
	}
	log.Debugf("auth: FloraApplications.ModifyRequest %s, add headed: X-Auth-App-Id: %d", req.URL, app.Id)
	req.Header.Set("X-Auth-App-Id", fmt.Sprintf("%d", app.Id))

	return nil
}

// MarvelNewModifier returns a request modifier that will set the query string
// at key with the given value. If the query string key already exists all
// values will be overwritten.
func MarvelNewModifier(applications []AuthData) martian.RequestModifier {
	m := AuthModifier{applications: make(map[uint8]AuthData)}
	for _, a := range applications {
		m.applications[a.Id] = a
	}
	return &m
}

// marvelModifierFromJSON takes a JSON message as a byte slice and returns
// a querystring.modifier and an error.
//
// Example JSON:
// {
//  "applications": [
//  {"id": 1, "name": "test app", "key": "secret_key"}
// ],
//  "scope": ["request", "response"]
// }
func marvelModifierFromJSON(b []byte) (*parse.Result, error) {
	msg := &MarvelModifierJSON{}

	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}

	return parse.NewResult(MarvelNewModifier(msg.Applications), msg.Scope)
}
