package htmlauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/diamondburned/caddy-htmlauth/internal/jank"
)

func init() {
	caddy.RegisterModule(&MultiAuth{})
	httpcaddyfile.RegisterHandlerDirective("multiauth", parseMultiAuthDirective)
}

// parseMultiAuthDirective parses the sharer directive like so:
//
//    sharer [<matcher>] <symlink>
//
func parseMultiAuthDirective(parser httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	auth := MultiAuth{
		Hosts: jank.CaddyfileHosts(parser),
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
			case "redirect":
				if !parser.AllArgs(&auth.Redirect) {
					return nil, parser.ArgErr()
				}
				if !strings.HasPrefix(auth.Redirect, "/") {
					return nil, parser.Err("redirect path doesn't have prefix /")
				}
			default:
				return nil, parser.Errf("unknown key %s", key)
			}
		}
	}

	return &auth, nil
}

// knownHosts contains the known hosts for multiauth.
var knownHosts = struct {
	hostMu sync.RWMutex
	hosts  map[string]map[string]*HTMLAuth // host -> username -> *HTMLAuth
}{
	hosts: map[string]map[string]*HTMLAuth{},
}

type knownUsers struct {
	users map[string]knownUser
}

type knownUser struct {
	hash   accountHash
	hasher caddyauth.Comparer

	fakePassword []byte // used to guard against timing attacks
}

func registerHTMLAuth(htmlauth *HTMLAuth) {
	key := strings.Join(htmlauth.Hosts, "\n")

	knownHosts.hostMu.Lock()
	defer knownHosts.hostMu.Unlock()

	users, ok := knownHosts.hosts[key]
	if !ok {
		users = map[string]*HTMLAuth{}
		knownHosts.hosts[key] = users
	}

	for username := range htmlauth.accountHashes {
		users[username] = htmlauth
	}
}

func deregisterHTMLAuth(htmlauth *HTMLAuth) {
	key := strings.Join(htmlauth.Hosts, "\n")

	knownHosts.hostMu.Lock()
	defer knownHosts.hostMu.Unlock()

	users, ok := knownHosts.hosts[key]
	if !ok {
		users = map[string]*HTMLAuth{}
		knownHosts.hosts[key] = users
	}

	for username := range htmlauth.accountHashes {
		delete(users, username)
	}

	if len(users) == 0 {
		delete(knownHosts.hosts, key)
	}
}

func findHTMLAuth(hosts []string, username string) *HTMLAuth {
	key := strings.Join(hosts, "\n")

	knownHosts.hostMu.RLock()
	defer knownHosts.hostMu.RUnlock()

	// Nil map lookups resolve to nil values.
	users, _ := knownHosts.hosts[key]
	user, _ := users[username]

	return user
}

type MultiAuth struct {
	Template string   `json:"template"`
	Redirect string   `json:"redirect"`
	Hosts    []string `json:"hosts"`
}

func (*MultiAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.multiauth",
		New: func() caddy.Module { return &MultiAuth{} },
	}
}

func (auth *MultiAuth) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	auth.Template = repl.ReplaceAll(auth.Template, "")

	return nil
}

func (auth *MultiAuth) getUser(username string) (*HTMLAuth, error) {
	htmlauth := findHTMLAuth(auth.Hosts, username)
	if htmlauth == nil {
		return nil, errors.New("no htmlauth block found for host")
	}

	return htmlauth, nil
}

func (auth *MultiAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Check if we have the username cookie. If we do, then immediately redirect
	// to the right resource.
	cookie, err := r.Cookie(usernameCookieName)
	if err == nil {
		// Use a Temporary Redirect to keep the method.
		http.Redirect(w, r, auth.userPath(r, cookie.Value), http.StatusTemporaryRedirect)
		return nil
	}

	switch r.Method {
	case "GET":
		return renderLogin(w, r, auth.Template)
	case "POST":
		// continue
	default:
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}

	if err := r.ParseForm(); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	username := r.FormValue("username")

	// Set the right ?origin so HTMLAuth's loginPOST can handle it correctly.
	r.Form.Set("origin", auth.userPath(r, username))

	htmlauth, err := auth.getUser(username)
	if err != nil {
		redirectWithQuery(w, r, url.Values{"err": {"unknown user"}})
		return nil
	}

	redirectTo, cookie, err := htmlauth.tryLogin(r)
	if err != nil {
		return err
	}

	if cookie != nil {
		http.SetCookie(w, cookie)
		http.SetCookie(w, usernameCookie(username, cookie.Expires))
	}

	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
	return nil
}

func (auth *MultiAuth) userPath(r *http.Request, username string) string {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("username", username)

	return repl.ReplaceAll(auth.Redirect, "/")
}

// redirectWithQuery redirects the client to the same path with added URL
// values.
func redirectWithQuery(w http.ResponseWriter, r *http.Request, add url.Values) {
	http.Redirect(w, r, uriWithQuery(r, add), http.StatusSeeOther)
}
