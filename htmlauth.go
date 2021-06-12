package htmlauth

import (
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"
)

func init() {
	caddy.RegisterModule(&HTMLAuth{})
	httpcaddyfile.RegisterHandlerDirective("htmlauth", parseHTMLAuthDirective)
}

// parseHTMLAuthDirective parses the sharer directive like so:
//
//    sharer [<matcher>] <symlink>
//
func parseHTMLAuthDirective(parser httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	auth := HTMLAuth{
		SessionAge: caddy.Duration(7 * 24 * time.Hour), // 1 week
	}

	for parser.Next() {
		if len(parser.RemainingArgs()) != 0 {
			return nil, parser.ArgErr()
		}

		for parser.NextBlock(0) {
			switch key := parser.Val(); key {
			case "template":
				if !parser.AllArgs(&auth.Template) {
					return nil, parser.ArgErr()
				}
			case "login_path":
				if !parser.AllArgs(&auth.LoginPath) {
					return nil, parser.ArgErr()
				}
				if !strings.HasPrefix(auth.LoginPath, "/") {
					return nil, parser.Err("login path doesn't have prefix /")
				}
			case "session_age":
				if !parser.NextArg() {
					return nil, parser.ArgErr()
				}
				d, err := caddy.ParseDuration(parser.Val())
				if err != nil {
					return nil, parser.Errf("invalid session_age: %v", err)
				}
				auth.SessionAge = caddy.Duration(d)
			case "basicauth":
				// Rewind the parser for parseAuthDirective.
				parser.Prev()

				ba, err := parseAuthDirective(parser)
				if err != nil {
					return nil, parser.Errf("basicauth error: %v", err)
				}
				auth.BasicAuth = *ba
			default:
				return nil, parser.Errf("unknown key %s", key)
			}
		}
	}

	return &auth, nil
}

type HTMLAuth struct {
	SessionAge caddy.Duration          `json:"session_age"`
	Template   string                  `json:"template"`
	LoginPath  string                  `json:"login_path"`
	BasicAuth  caddyauth.HTTPBasicAuth `json:"basic_auth"`

	sessions      sync.Map // token -> *session
	fakePassword  []byte   // I hate unexported fields.
	accountHashes map[string]accountHash
}

type accountHash struct{ password, salt []byte }

func (*HTMLAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.htmlauth",
		New: func() caddy.Module { return &HTMLAuth{} },
	}
}

func (auth *HTMLAuth) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()

	auth.LoginPath = repl.ReplaceAll(path.Clean(auth.LoginPath), "")
	auth.Template = repl.ReplaceAll(auth.Template, "")

	if err := auth.BasicAuth.Provision(ctx); err != nil {
		return err
	}

	// if supported, generate a fake password we can compare against if needed
	if hasher, ok := auth.BasicAuth.Hash.(caddyauth.Hasher); ok {
		auth.fakePassword, _ = hasher.Hash([]byte("antitiming"), []byte("fakesalt"))
	}

	auth.accountHashes = make(map[string]accountHash, len(auth.BasicAuth.Accounts))
	for username, account := range auth.BasicAuth.Accounts {
		// OK to ignore these errors, since provisioning BasicAuth already
		// checks them.
		pass, _ := base64.StdEncoding.DecodeString(account.Password)
		salt, _ := base64.StdEncoding.DecodeString(account.Salt)

		auth.accountHashes[username] = accountHash{
			password: pass, salt: salt,
		}
	}

	return nil
}

func (auth *HTMLAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Stage 0: Delegate to the login page if this is the path.
	if strings.HasPrefix(r.URL.Path, auth.LoginPath) {
		switch r.Method {
		case "GET":
			return auth.renderLogin(w, r)
		case "POST":
			return auth.loginPOST(w, r)
		default:
			return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
		}
	}
	basePath := basePath(r, oldURL(r).Path)

	// Stage 1: check if the user is already authenticated. Authentication using
	// the HTML form will set a session_id cookie.
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		// Verify that the session token is valid.
		v, ok := auth.sessions.Load(cookie.Value)
		if ok {
			ses := v.(*session)

			expiry, ok := ses.isValid(auth.SessionAge)
			if ok {
				// Set the http.auth.user placeholders.
				sessionSetReplacer(r, ses.username, expiry)
				// Update the cookie.
				http.SetCookie(w, sessionCookie(basePath, cookie.Value, expiry))

				return next.ServeHTTP(w, r)
			}
		}
	}

	// Stage 2: try to see if the user is trying to do basic auth.
	if r.Header.Get("Authentication") != "" {
		user, ok, err := auth.BasicAuth.Authenticate(w, r)
		if err != nil {
			return err
		}
		if !ok {
			// Return a status code instead, since this might be a scripting
			// API.
			return caddyhttp.Error(http.StatusForbidden, nil)
		}

		// Set the http.auth.user placeholders.
		sessionSetReplacer(r, user.ID, time.Time{})

		return next.ServeHTTP(w, r)
	}

	// Stage 3: the user is not authenticated; redirect to the login path while
	// preserving the redirect URL.
	oldURL := oldURL(r)
	origin := url.Values{
		"origin": {oldURL.RequestURI()},
	}

	loginPath := path.Join(basePath, auth.LoginPath) + "?" + origin.Encode()
	http.Redirect(w, r, loginPath, http.StatusSeeOther)

	return nil
}

func basePath(r *http.Request, old string) string {
	return strings.TrimSuffix(old, path.Clean(r.URL.Path))
}

func oldURL(r *http.Request) *url.URL {
	oldReq := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
	v := *oldReq.URL // copy so we don't mutate
	return &v
}

// redirectWithQuery redirects the client to the same path with added URL
// values.
func redirectWithQuery(w http.ResponseWriter, r *http.Request, add url.Values) {
	old := oldURL(r)
	qry := old.Query()
	for k, v := range add {
		qry[k] = v
	}
	old.RawQuery = qry.Encode()
	http.Redirect(w, r, old.RequestURI(), http.StatusSeeOther)
}

func (auth *HTMLAuth) loginPOST(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		redirectWithQuery(w, r, url.Values{"err": {err.Error()}})
		return nil
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" {
		redirectWithQuery(w, r, url.Values{"err": {"Username cannot be empty."}})
		return nil
	}
	if password == "" {
		redirectWithQuery(w, r, url.Values{"err": {"Password cannot be empty."}})
		return nil
	}

	account, ok := auth.accountHashes[username]
	if !ok {
		// Use the fake password to prevent timing attacks. We can directly set
		// account's fields because it's a copy.
		account.password = auth.fakePassword
	}

	correct, err := auth.BasicAuth.Hash.Compare(account.password, []byte(password), account.salt)
	if err != nil {
		log.Println("htmlauth: hash compare error:", err)
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Incorrect password; redirect back to the login page.
	if !correct {
		// Login POST is in the same path, so we can just redirect to a GET.
		redirectWithQuery(w, r, url.Values{"err": {"Incorrect username or password."}})
		return nil
	}

	// Authentication pass; store the session.
	session := newSession(username, auth.SessionAge)
	expires := time.Unix(0, session.expireAt)

	var token string
	for {
		token = genSessionToken()

		// Use LoadOrStore to ensure that we're not overriding the token. If we are,
		// then we should regenerate the token.
		_, duplicate := auth.sessions.LoadOrStore(token, session)
		if duplicate {
			// Yield the goroutine so we don't eat all resources.
			runtime.Gosched()
			continue
		}

		break
	}

	sessionSetReplacer(r, username, expires)

	basePath := basePath(r, oldURL(r).Path)
	http.SetCookie(w, sessionCookie(basePath, token, expires))

	// See if we have the origin query. If we do, then redirect the user back
	// there. Otherwise, redirect to the base path.
	if origin := r.FormValue("origin"); origin != "" {
		http.Redirect(w, r, origin, http.StatusSeeOther)
		return nil
	}

	http.Redirect(w, r, basePath, http.StatusSeeOther)
	return nil
}

func (auth *HTMLAuth) renderLogin(w http.ResponseWriter, r *http.Request) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	root, ok := repl.GetString("http.vars.root")
	if !ok || !strings.HasPrefix(root, "/") {
		root = "/" // OS root
	}

	templateCtx := templates.TemplateContext{
		Root:       http.Dir(root),
		Req:        r,
		RespHeader: templates.WrappedHeader{Header: w.Header()},
	}

	var err error

	tmpl := templateCtx.NewTemplate(filepath.Base(auth.Template))
	tmpl, err = tmpl.ParseFiles(auth.Template)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := tmpl.Execute(w, templateCtx); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	return nil
}
