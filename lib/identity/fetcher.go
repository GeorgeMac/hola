package identity

// validate at compile time that FetcherFunc implements Fetcher.
var _ Fetcher = FetcherFunc(nil)

// Fetcher is an interface which describes the mechanism required
// to be implemented by a storage layer, used for fetching identities
// for a given key.
type Fetcher interface {
	Fetch(key string) (identity Identity, ok bool, err error)
}

// FetcherFunc implements the Fetcher interface.
// This allows for simple functions to be used as a Fetcher.
type FetcherFunc func(string) (Identity, bool, error)

// Fetch takes an key string and returns the associated identity,
// If the identity is not present the returned boolean WILL BE FALSE.
// If something else went wrong during the fetch process err WILL NOT BE NIL.
func (s FetcherFunc) Fetch(key string) (Identity, bool, error) {
	return s(key)
}
