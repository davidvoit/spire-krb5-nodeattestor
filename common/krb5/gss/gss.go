package gss

// GSSContext defines the interface for GSSAPI/SSPI operations.
// This allows abstracting the differences between GSSAPI on POSIX and SSPI on Windows.
type GSSContext interface {
	// Step performs a single step of the security context negotiation.
	// It takes an input token from the peer and returns an output token to be sent to the peer.
	// done is true when the negotiation is complete.
	Step(inputToken []byte) (outputToken []byte, done bool, err error)

	// Wrap protects a message (signs/encrypts).
	Wrap(msg []byte) ([]byte, error)

	// Unwrap verifies/decrypts a message.
	Unwrap(msg []byte) ([]byte, error)

	// Close releases any resources associated with the context.
	Close() error
}

// NewClientContext creates a new GSS client context using raw Kerberos (OID 1.2.840.113554.1.2.2).
// targetName is the principal name in GSSAPI syntax (e.g. "HOST@server.example.com").
// keytabPath is optional - On Windows it is always ignored
func NewClientContext(targetName string, keytabPath ...string) (GSSContext, error) {
	kt := ""
	if len(keytabPath) > 0 {
		kt = keytabPath[0]
	}
	return newClientContext(targetName, kt)
}

// NewServerContext creates a new GSS server context using raw Kerberos (OID 1.2.840.113554.1.2.2).
// keytabPath is optional - On Windows it is always ignored
func NewServerContext(keytabPath ...string) (GSSContext, error) {
	kt := ""
	if len(keytabPath) > 0 {
		kt = keytabPath[0]
	}
	return newServerContext(kt)
}
