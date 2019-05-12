package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	"github.com/CossackPyra/pyraconv"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/skip2/go-qrcode"
)

// that app has not tested with HTTPS
// Adjust SERVER_NAME_CHANGE_IT to make URLs work.
//

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key         = []byte("super-secret-key")
	store       = sessions.NewCookieStore(key)
	db          = InitPassDB()
	AgeCheckURL = "https://deep.reallyme.net/agecheck"
	ReturnURL   = "http://SERVER_NAME_CHANGE_IT:9280/"
	PostbackURL = "http://SERVER_NAME_CHANGE_IT:9280/api"
	CookieName  = "cookie-name"
	AgeGateId   = "agid"
	URL         = "url"
	Postback    = "postback"
	JWT_PUB     = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6YjRtcjhqcHh3NXJSU2pqK1NEQQo2cG9GNlFmaXp4dEtUZlVWQTYwTG1XTXJQeS93MWF4KzBsb1lxWWRYT2lVRmhETWhSQ2JiQjVaTmhzcDFEbklnCm03NTdVMldIaXJhOVFQcUNXTmo4Ymo0L1dxN0FwT3hFT0ZQVWFLeTVZZlRjaWQxU3VLWHpZNDNWa21NYUdUYnUKOXFJTWRzcitHU2lTTmdzZlNEcVNIeG4wL0Z5aFFkZTcwbWZjMTh1V3h5ZGVXTm5hRkhjeUZpMWFsbWUyZGREZQpHSlRta043YkZUT2ZHZXM5RkdDZWZzckI3MDRMcE8wcHo2ZjhHNlhsVmZQb0IwY2liWno3SlpHU0g5bHB1RkVkCm5MM2RVRFdvL3BBNzR3REJsSncrVThZWkN3eG1jeFZLVWRwejV1ZUJOMGc1WnN0czhjQjV6Y2V2aHZHSUIzazMKOVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
	verifyKey   *rsa.PublicKey
)

type PassDB struct {
	mu sync.Mutex
	m  map[string]bool
} // END type PassDB

func InitPassDB() (result *PassDB) {
	result = &PassDB{
		m: map[string]bool{},
	}
	return result
} // END func InitPassDB

func (p *PassDB) Open(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.m[id] = true
} // END func (p *PassDB) Open

func (p *PassDB) Check(id string) (result bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.m[id]
} // END func (p *PassDB) Check

func (p *PassDB) Debug() (result []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var b bytes.Buffer

	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	enc.Encode(p.m)

	return b.Bytes()

} // END func (p *PassDB) Check

// index
// porn
// api

func main() {

	var err error
	verifyBytes, err := base64.StdEncoding.DecodeString(JWT_PUB)
	if err != nil {
		panic(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		panic(err)
	}

	mux1 := http.NewServeMux()

	mux1.HandleFunc("/", hIndex)
	mux1.HandleFunc("/18plus", h18plus)
	mux1.HandleFunc("/api", hApi)
	mux1.HandleFunc("/qr", hQr)
	mux1.HandleFunc("/logout", hLogout)
	mux1.HandleFunc("/debug", hDebug)

	http.ListenAndServe(":9280", mux1)

} // END func main

func makeUrl(uuid1 string) (result string) {

	v := url.Values{}
	v.Add(AgeGateId, uuid1)
	v.Add(URL, ReturnURL)
	v.Add(Postback, PostbackURL)

	result = fmt.Sprintf(
		"%s?%s",
		AgeCheckURL,
		v.Encode(),
	)

	return

} // END func makeUrl

func hIndex(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, CookieName)
	w.Header().Set("Cache-Control", "no-store")

	uuid1, ok := session.Values[AgeGateId].(string)
	if !ok {
		uuid1 = uuid.New().String()
		session.Values[AgeGateId] = uuid1
		session.Save(r, w)
	} // END if !ok

	t, err := template.New("index").Parse(`
	<html>
		<head>
			<title>P Site</title>
		</head>
		<body>
			<p>
				<img src="{{ .Image }}" border="0" />
			</p>
			<p>
				<a href="{{ .URL }}">{{ .URL }}</a>
			</p>
			<p>
				<a href="{{ .Plus18 }}">{{ .Plus18 }}</a>
			</p>
			<p>
				<a href="{{ .Logout }}">{{ .Logout }}</a>
			</p>
			<p>
				<a href="{{ .Debug }}">{{ .Debug }}</a>
			</p>
		</body>
	</html>
	`)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusInternalServerError)
		return
	}

	u1 := makeUrl(uuid1)

	if err := t.Execute(
		w,
		map[string]interface{}{
			"Image":  "qr",
			"URL":    u1,
			"Plus18": "/18plus",
			"Logout": "/logout",
			"Debug":  "/debug",
		},
	); err != nil {
		http.Error(w, "Forbidden", http.StatusInternalServerError)
		return
	}

} // END func hIndex

func h18plus(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, CookieName)
	w.Header().Set("Cache-Control", "no-store")

	uuid1, ok := session.Values[AgeGateId].(string)
	if !ok || uuid1 == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if db.Check(uuid1) {
		fmt.Fprintln(w, "The cake is a lie!")
	} else {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}

} // END func h18plus

func hApi(w http.ResponseWriter, r *http.Request) {
	// session, _ := store.Get(r, "cookie-name")

	// GET JWT
	// parse
	// db.Open(id)

	// r.ParseForm()
	// token := r.Form.Get("jwt")

	fmt.Printf("hApi\n")

	dec := json.NewDecoder(r.Body)

	var m1 map[string]interface{}

	err := dec.Decode(&m1)
	if err != nil {
		fmt.Printf("dec.Decode: %v\n", err)
		return
	}

	token := pyraconv.ToString(m1["jwt"])

	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		fmt.Printf("jwt.Parse: %v\n", err)
		return
	}

	m := t.Claims.(jwt.MapClaims)

	agid := pyraconv.ToString(m["agid"])

	fmt.Printf("hApi_ %#v %s", m, agid)

	db.Open(agid)

} // END func hApi

func hQr(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, CookieName)
	w.Header().Set("Cache-Control", "no-store")

	uuid1, ok := session.Values[AgeGateId].(string)
	if !ok || uuid1 == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	u1 := makeUrl(uuid1)

	png, err := qrcode.Encode(u1, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "image/png")
	w.Write(png)

	return
} // END func hQr

func hLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, CookieName)
	w.Header().Set("Cache-Control", "no-store")

	delete(session.Values, AgeGateId)
	session.Save(r, w)

	http.Redirect(w, r, "/", 301)

} // END func hLogout

func hDebug(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, CookieName)
	w.Header().Set("Cache-Control", "no-store")

	var b bytes.Buffer

	m1 := map[string]interface{}{}

	for k1, v1 := range session.Values {
		m1[fmt.Sprintf("%v", k1)] = v1
	} // END for

	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	err := enc.Encode(m1)
	if err != nil {
		fmt.Fprintf(w, "Error1: %s\n", err.Error())
	}

	w.Header().Set("content-type", "text/json")
	w.Write(b.Bytes())

	w.Write([]byte("\n\n------\n\n"))

	w.Write(db.Debug())

} // END func hDebug
