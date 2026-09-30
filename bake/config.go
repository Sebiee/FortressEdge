package bake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Config is fortress.yml as fields, one per key, in the order YAML writes
// them. A field left at its zero value leaves its key out, so the edge uses
// the key's default.
type Config struct {
	// ClientCA is the PEM CA certificate that signs the dark-node, operator,
	// and log-reader certificates: exactly one certificate. Required.
	ClientCA string `yaml:"client_ca"`
	// ACME is the ACME directory URL. Empty is Let's Encrypt.
	ACME string `yaml:"acme"`
	// ACMECA is the PEM CA that signed the ACME directory's HTTPS
	// certificate. Empty trusts the system roots.
	ACMECA string `yaml:"acme_ca"`
	// NTP are the time servers the edge keeps its clock to, each host or
	// host:port: several, so one that is wrong is outvoted. Empty is
	// pool.ntp.org.
	NTP []string `yaml:"ntp"`
	// RenewInterval is how often ACME certificates are checked, a duration
	// such as 4h. Empty is 4h.
	RenewInterval string `yaml:"renew_interval"`
	// QUIC lets dark nodes connect over QUIC on UDP 443 too.
	QUIC bool `yaml:"quic"`
}

// Check reports what is wrong with c, as the edge would. An error names the
// fortress.yml key it is about, as "fortress.yml: acme: ...".
func (c Config) Check() error { return Check(c.YAML()) }

// Keys lists fortress.yml's keys in the order of Config's fields.
func Keys() []string {
	t := reflect.TypeFor[Config]()
	keys := make([]string, t.NumField())
	for i := range keys {
		keys[i] = t.Field(i).Tag.Get("yaml")
	}
	return keys
}

// YAML is c as fortress.yml: the keys it sets, in Keys' order, strings
// quoted and PEM as block scalars. The same Config gives the same bytes,
// whatever YAML library another version of this package would use.
func (c Config) YAML() []byte {
	var b bytes.Buffer
	v := reflect.ValueOf(c)
	for i, key := range Keys() {
		switch f := v.Field(i); f.Kind() {
		case reflect.String:
			s := strings.TrimSpace(f.String())
			switch {
			case s == "":
			case strings.Contains(s, "\n"):
				fmt.Fprintf(&b, "%s: |\n", key)
				for line := range strings.SplitSeq(s, "\n") {
					fmt.Fprintf(&b, "  %s\n", strings.TrimRight(line, " \t\r"))
				}
			default:
				q, _ := json.Marshal(s) // a JSON string is a YAML double-quoted scalar
				fmt.Fprintf(&b, "%s: %s\n", key, q)
			}
		case reflect.Bool:
			if f.Bool() {
				fmt.Fprintf(&b, "%s: true\n", key)
			}
		case reflect.Int:
			if f.Int() != 0 {
				fmt.Fprintf(&b, "%s: %s\n", key, strconv.FormatInt(f.Int(), 10))
			}
		case reflect.Slice: // of strings: a flow sequence of JSON strings
			var items []string
			for _, item := range f.Interface().([]string) {
				if item = strings.TrimSpace(item); item != "" {
					q, _ := json.Marshal(item)
					items = append(items, string(q))
				}
			}
			if len(items) > 0 {
				fmt.Fprintf(&b, "%s: [%s]\n", key, strings.Join(items, ", "))
			}
		default:
			panic("bake: Config field " + key + " of a kind YAML does not write")
		}
	}
	return b.Bytes()
}
