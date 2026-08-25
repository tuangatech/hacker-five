package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
)

// TestDSLEval_VarsFallback locks in the Vars addition to dsl.Context — added
// for the native template engine's condition: field (Step 3), which
// evaluates against already-bound template variables, not an HTTP response.
func TestDSLEval_VarsFallback(t *testing.T) {
	ctx := dsl.Context{Vars: map[string]string{"auth_token": "tok-abc"}}

	val, err := dsl.Eval(`auth_token != ""`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`auth_token == "tok-abc"`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

func TestDSLEval_UnboundVarStillErrors(t *testing.T) {
	_, err := dsl.Eval(`nonexistent_var != ""`, dsl.Context{Vars: map[string]string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown identifier "nonexistent_var"`)
}

// TestDSLEval_BuiltinsTakePriorityOverVars confirms a bound var named the
// same as a built-in (status_code/body/header) can't shadow it — Context's
// doc comment on Vars states this ordering explicitly.
func TestDSLEval_BuiltinsTakePriorityOverVars(t *testing.T) {
	ctx := dsl.Context{StatusCode: 200, Vars: map[string]string{"status_code": "should-not-be-used"}}
	val, err := dsl.Eval(`status_code == 200`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}
