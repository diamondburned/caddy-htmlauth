package htmlauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const sessionCookieName = "session"

type session struct {
	mutex    sync.Mutex
	expireAt int64

	// constants
	username string
}

func newSession(username string, age caddy.Duration) *session {
	return &session{
		expireAt: time.Now().Add(time.Duration(age)).UnixNano(),
		username: username,
	}
}

// isValid checks if the session is still valid. If yes, it updates the time.
func (ses *session) isValid(age caddy.Duration) (expiry time.Time, ok bool) {
	now := time.Now().UnixNano()

	ses.mutex.Lock()
	defer ses.mutex.Unlock()

	if ses.expireAt > now {
		ses.expireAt = now + int64(age)
		return time.Unix(0, ses.expireAt), true
	}

	return time.Unix(0, ses.expireAt), false
}

func sessionCookie(basePath, token string, expiry time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Expires:  expiry,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     basePath,
	}
}

// sessionSetReplacer sets .auth.user.id. If expiry is not zero, then the
// session is implied.
func sessionSetReplacer(r *http.Request, username string, expiry time.Time) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.auth.user.id", username)

	if !expiry.IsZero() {
		repl.Set("http.auth.user.session", "yes")
		repl.Set("http.auth.user.expires", expiry.Format(time.RFC3339))
	}
}

// sessionIncrementor is an atomically incremented integer used for generating
// the token. It takes up 8 bytes. It exists in case the system's random
// generator isn't good enough.
var sessionIncrementor uint32

// genSessionToken generates the session token. The returned token will always
// be within ASCII range.
func genSessionToken() string {
	// Combine the incrementor and the timestamp in case the system's random
	// generator doesn't have enough entropy.
	//    4 bytes incrementor
	//    4 bytes timestamp, unix
	//   16 bytes entropy
	buf := make([]byte, 4+4+16)

	add := atomic.AddUint32(&sessionIncrementor, 1)
	binary.BigEndian.PutUint32(buf[0:], add)

	now := time.Now().Unix()
	binary.BigEndian.PutUint32(buf[4:], uint32(now))

	_, err := rand.Read(buf[8:])
	if err != nil {
		// no hope left in this world
		log.Panic("cannot generate random:", err)
	}

	// About 41 bytes-ish.
	return base64.RawURLEncoding.EncodeToString(buf)
}
