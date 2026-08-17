//go:build !windows

package gss

import (
	"fmt"
	"strings"

	_ "github.com/golang-auth/go-gssapi-c"
	gssapi "github.com/golang-auth/go-gssapi/v3"
)

var gssProvider = gssapi.MustNewProvider("github.com/golang-auth/go-gssapi-c")

type posixGSSContext struct {
	ctx        gssapi.SecContext
	cred       gssapi.Credential
	keytabPath string
}

func newClientContext(targetName, keytabPath string) (GSSContext, error) {
	var cred gssapi.Credential
	if keytabPath != "" {
		if p, ok := gssProvider.(gssapi.ProviderExtCredStore); ok {
			var err error
			cred, err = p.AcquireCredentialFrom(nil, []gssapi.GssMech{gssapi.GSS_MECH_KRB5}, gssapi.CredUsageInitiateOnly, nil, gssapi.WithCredStoreClientKeytab(keytabPath))
			if err != nil {
				cred = nil
			}
		}
	}

	name, err := gssProvider.ImportName(targetName, gssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		if cred != nil {
			_ = cred.Release()
		}
		return nil, fmt.Errorf("failed to import name: %v", err)
	}
	defer func() { _ = name.Release() }()

	flags := gssapi.ContextFlagMutual | gssapi.ContextFlagConf | gssapi.ContextFlagInteg | gssapi.ContextFlagReplay | gssapi.ContextFlagSequence
	ctx, err := gssProvider.InitSecContext(name,
		gssapi.WithInitiatorFlags(flags),
		gssapi.WithInitiatorCredential(cred),
		gssapi.WithInitiatorMech(gssapi.GSS_MECH_KRB5),
	)
	if err != nil {
		if cred != nil {
			_ = cred.Release()
		}
		return nil, fmt.Errorf("failed to initialize security context: %v", err)
	}

	return &posixGSSContext{
		ctx:        ctx,
		cred:       cred,
		keytabPath: keytabPath,
	}, nil
}

func newServerContext(keytabPath string) (GSSContext, error) {
	var cred gssapi.Credential
	if keytabPath != "" {
		if p, ok := gssProvider.(gssapi.ProviderExtCredStore); ok {
			var err error
			cred, err = p.AcquireCredentialFrom(nil, []gssapi.GssMech{gssapi.GSS_MECH_KRB5}, gssapi.CredUsageAcceptOnly, nil, gssapi.WithCredStoreServerKeytab(keytabPath))
			if err != nil {
				cred = nil
			}
		}
	}

	ctx, err := gssProvider.AcceptSecContext(gssapi.WithAcceptorCredential(cred))
	if err != nil {
		if cred != nil {
			_ = cred.Release()
		}
		return nil, fmt.Errorf("failed to accept security context: %v", err)
	}

	return &posixGSSContext{
		ctx:        ctx,
		cred:       cred,
		keytabPath: keytabPath,
	}, nil
}

func (c *posixGSSContext) Step(inputToken []byte) ([]byte, bool, error) {
	outToken, _, err := c.ctx.Continue(inputToken)
	if err != nil {
		return nil, false, err
	}
	return outToken, !c.ctx.ContinueNeeded(), nil
}

func (c *posixGSSContext) Wrap(msg []byte) ([]byte, error) {
	wrapped, _, err := c.ctx.Wrap(msg, true, 0)
	if err != nil {
		return nil, err
	}
	return wrapped, nil
}

func (c *posixGSSContext) Unwrap(msg []byte) ([]byte, error) {
	unwrapped, _, _, err := c.ctx.Unwrap(msg)
	if err != nil {
		return nil, err
	}
	return unwrapped, nil
}

func (c *posixGSSContext) Close() error {
	var errs []string
	if c.ctx != nil {
		if _, err := c.ctx.Delete(); err != nil {
			errs = append(errs, fmt.Sprintf("failed to delete context: %v", err))
		}
	}
	if c.cred != nil {
		if err := c.cred.Release(); err != nil {
			errs = append(errs, fmt.Sprintf("failed to release credential: %v", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
