package htmlauth

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"
)

// uriWithQuery creates a request URI from the original URL with the given value
// added.
func uriWithQuery(r *http.Request, add url.Values) string {
	old := oldURL(r)
	qry := old.Query()
	for k, v := range add {
		qry[k] = v
	}
	old.RawQuery = qry.Encode()
	return old.RequestURI()
}

func renderLogin(w http.ResponseWriter, r *http.Request, path string) error {
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

	tmpl := templateCtx.NewTemplate(filepath.Base(path))
	tmpl, err = tmpl.ParseFiles(path)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := tmpl.Execute(w, templateCtx); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	return nil
}
