// Package config holds meshd's configuration file schema, merge precedence,
// and the default OpenDHT roster endpoints.
package config

// DefaultProxies are the public OpenDHT endpoints shipped as defaults,
// matching stunmesh's contrib plugin defaults (both are the Jami proxies).
var DefaultProxies = []string{
	"https://dhtproxy3.jami.net",
	"https://dhtproxy2.jami.net",
}
