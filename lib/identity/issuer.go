package identity

// validate at compile time that IssuerFunc implements Issuer.
var _ Issuer = IssuerFunc(nil)

// Issuer is an interface which describes the mechanism required
// to be implemented by a storage layer, in order to issue a new
// identity.
type Issuer interface {
	Issue() (identity Identity, err error)
}

// IssuerFunc implements the Issuer interface.
// This allows for simple functions to be used as an Issuer.
type IssuerFunc func() (Identity, error)

// Issue takes an key string and returns the associated identity,
// If the identity is not present the returned boolean WILL BE FALSE.
// If something else went wrong during the fetch process err WILL NOT BE NIL.
func (i IssuerFunc) Issue() (Identity, error) {
	return i()
}
