package masque

import "github.com/xen0bit/veepin/internal/masque/http3"

// connect-ip is the :protocol token that turns an Extended CONNECT into an IP
// tunnel (RFC 9484 §3).
const connectIPProtocol = "connect-ip"

// ConnectIPPath builds the request path from the URI template
// /.well-known/masque/ip/{target}/{ipproto}/ (RFC 9484 §3.1). A full-tunnel
// client uses "*" for both, meaning "any destination, any IP protocol"; the
// server decides what it will actually route.
func ConnectIPPath(target, ipproto string) string {
	if target == "" {
		target = "*"
	}
	if ipproto == "" {
		ipproto = "*"
	}
	return "/.well-known/masque/ip/" + target + "/" + ipproto + "/"
}

// ProxyAuthorizationField carries the client's bearer token in a CONNECT
// request (RFC 9110 §11.7.1). HTTP/3 field names are lower-case.
const ProxyAuthorizationField = "proxy-authorization"

// WithToken appends the proxy-authorization field to a CONNECT request's
// fields when token is non-empty.
func WithToken(fields []http3.Field, token string) []http3.Field {
	if token == "" {
		return fields
	}
	return append(fields, http3.Field{Name: ProxyAuthorizationField, Value: "Bearer " + token})
}

// ConnectIPHeaders builds the pseudo-header set for a CONNECT-IP request. The
// capsule-protocol field is mandatory: it is what tells the proxy the stream
// body is capsules rather than an opaque payload.
func ConnectIPHeaders(authority, path string) []http3.Field {
	return []http3.Field{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
		{Name: ":protocol", Value: connectIPProtocol},
		{Name: "capsule-protocol", Value: "?1"},
	}
}

// IsConnectIP reports whether a decoded request is a CONNECT-IP request the
// server should accept. The three pseudo-headers are what RFC 9484 §3 requires;
// the path is validated separately by the router.
func IsConnectIP(fields []http3.Field) bool {
	var method, protocol string
	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":protocol":
			protocol = f.Value
		}
	}
	return method == "CONNECT" && protocol == connectIPProtocol
}
