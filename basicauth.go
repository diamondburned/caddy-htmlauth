package htmlauth

import (
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

// parseAuthDirective is copy-pasted from the Caddy repository.
func parseAuthDirective(parser httpcaddyfile.Helper) (*caddyauth.HTTPBasicAuth, error) {
	ba := caddyauth.HTTPBasicAuth{
		HashCache: new(caddyauth.Cache),
	}

	for parser.Next() {
		args := parser.RemainingArgs()

		var hashName string
		switch len(args) {
		case 0:
			hashName = "bcrypt"
		case 1:
			hashName = args[0]
		case 2:
			hashName = args[0]
			ba.Realm = args[1]
		default:
			return nil, parser.ArgErr()
		}

		var cmp caddyauth.Comparer
		switch hashName {
		case "bcrypt":
			cmp = caddyauth.BcryptHash{}
		case "scrypt":
			cmp = caddyauth.ScryptHash{}
		default:
			return nil, parser.Errf("unrecognized hash algorithm: %s", hashName)
		}

		ba.HashRaw = caddyconfig.JSONModuleObject(cmp, "algorithm", hashName, nil)

		for nesting := parser.Nesting(); parser.NextBlock(nesting); {
			username := parser.Val()

			var b64Pwd, b64Salt string
			parser.Args(&b64Pwd, &b64Salt)
			if parser.NextArg() {
				return nil, parser.ArgErr()
			}

			if username == "" || b64Pwd == "" {
				return nil, parser.Err("username and password cannot be empty or missing")
			}

			if strings.Contains(username, ":") {
				return nil, parser.Errf("username %q contains illegal colon ':'", username)
			}

			ba.AccountList = append(ba.AccountList, caddyauth.Account{
				Username: username,
				Password: b64Pwd,
				Salt:     b64Salt,
			})
		}
	}

	return &ba, nil
}
