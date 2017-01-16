package auth

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ScopesFromContext_OK(t *testing.T) {
	scopes := []string{"resource.action:10", "other.action:5"}
	ctxt := context.WithValue(context.TODO(), ScopesKey.String(), scopes)

	found, ok, err := ScopesFromContext(ctxt)
	require.Nil(t, err)
	require.True(t, ok)
	assert.Equal(t, found, scopes)
}

func Test_ScopesFromContext_NotFound(t *testing.T) {
	found, ok, err := ScopesFromContext(context.TODO())
	require.Nil(t, err)
	assert.False(t, ok)
	assert.Nil(t, found)
}

func Test_ScopesFromContext_Error(t *testing.T) {
	scopes := "should be an array"
	ctxt := context.WithValue(context.TODO(), ScopesKey.String(), scopes)

	found, ok, err := ScopesFromContext(ctxt)
	assert.Equal(t, errors.Cause(err), ErrContextUnexpectedScopesType)
	assert.Error(t, err, `unexpected type "should be an array": invalid type for scopes within context`)
	assert.False(t, ok)
	assert.Nil(t, found)
}
