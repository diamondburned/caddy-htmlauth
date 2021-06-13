// Package jank contains weird and ugly shenanigans to work around possibly ugly
// designs.
package jank

import (
	"reflect"
	"unsafe"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

// CaddyfileHosts returns the keys of the parent block from the given Caddyfile
// helper.
func CaddyfileHosts(h httpcaddyfile.Helper) []string {
	v := getField(&h, "parentBlock", reflect.TypeOf(caddyfile.ServerBlock{}))
	return v.(*caddyfile.ServerBlock).Keys
}

// BasicAuthFakePw gets the fakePassword field of a HTTPBasicAuth.
func BasicAuthFakePw(ba caddyauth.HTTPBasicAuth) []byte {
	v := getField(&ba, "fakePassword", reflect.TypeOf([]byte(nil)))
	return *(v.(*[]byte))
}

func getField(ptr interface{}, field string, typ reflect.Type) interface{} {
	v := reflect.ValueOf(ptr).Elem()
	f := v.FieldByName(field)
	return reflect.NewAt(typ, unsafe.Pointer(f.UnsafeAddr())).Interface()
}
