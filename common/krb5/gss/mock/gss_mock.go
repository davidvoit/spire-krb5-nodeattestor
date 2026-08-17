package mock

import (
	"errors"
	"fmt"

	"spire-krb5-nodeattestor/common/krb5/gss"
)

type stepHandler func(inputToken []byte) (outputToken []byte, done bool, err error)
type wrapHandler func(msg []byte) ([]byte, error)
type unwrapHandler func(msg []byte) ([]byte, error)

type GSSContextBuilder struct {
	steps  []stepHandler
	wrap   wrapHandler
	unwrap unwrapHandler
}

func NewGSSContext() *GSSContextBuilder {
	return &GSSContextBuilder{}
}

func (b *GSSContextBuilder) ExpectThenStep(inputToken, outputToken []byte, done bool) *GSSContextBuilder {
	clone := *b
	clone.steps = append(append([]stepHandler{}, b.steps...), func(actual []byte) ([]byte, bool, error) {
		if string(actual) != string(inputToken) {
			return nil, false, fmt.Errorf("gss mock: unexpected Step input: want %q got %q", inputToken, actual)
		}
		return outputToken, done, nil
	})
	return &clone
}

func (b *GSSContextBuilder) FailStep(err error) *GSSContextBuilder {
	clone := *b
	clone.steps = append(append([]stepHandler{}, b.steps...), func([]byte) ([]byte, bool, error) {
		return nil, false, err
	})
	return &clone
}

func (b *GSSContextBuilder) ExpectAndWrap(input, output []byte) *GSSContextBuilder {
	clone := *b
	clone.wrap = func(msg []byte) ([]byte, error) {
		if string(msg) != string(input) {
			return nil, fmt.Errorf("gss mock: unexpected Wrap input: want %q got %q", input, msg)
		}
		return output, nil
	}
	return &clone
}

func (b *GSSContextBuilder) ExpectAndUnwrap(input, output []byte) *GSSContextBuilder {
	clone := *b
	clone.unwrap = func(msg []byte) ([]byte, error) {
		if string(msg) != string(input) {
			return nil, fmt.Errorf("gss mock: unexpected Unwrap input: want %q got %q", input, msg)
		}
		return output, nil
	}
	return &clone
}

func (b *GSSContextBuilder) Build() (gss.GSSContext, func(...string) (gss.GSSContext, error)) {
	ctx := &mockGSSContext{
		steps:  append([]stepHandler{}, b.steps...),
		wrap:   b.wrap,
		unwrap: b.unwrap,
	}
	return ctx, func(...string) (gss.GSSContext, error) { return ctx, nil }
}

func (b *GSSContextBuilder) BuildClient() (gss.GSSContext, func(string, ...string) (gss.GSSContext, error)) {
	ctx, _ := b.Build()
	return ctx, func(string, ...string) (gss.GSSContext, error) { return ctx, nil }
}

type mockGSSContext struct {
	steps  []stepHandler
	wrap   wrapHandler
	unwrap unwrapHandler
}

func (m *mockGSSContext) Step(inputToken []byte) ([]byte, bool, error) {
	if len(m.steps) == 0 {
		return nil, false, errors.New("gss mock: unexpected Step call")
	}
	handler := m.steps[0]
	m.steps = m.steps[1:]
	return handler(inputToken)
}

func (m *mockGSSContext) Wrap(msg []byte) ([]byte, error) {
	if m.wrap == nil {
		return nil, errors.New("gss mock: unexpected Wrap call")
	}
	return m.wrap(msg)
}

func (m *mockGSSContext) Unwrap(msg []byte) ([]byte, error) {
	if m.unwrap == nil {
		return nil, errors.New("gss mock: unexpected Unwrap call")
	}
	return m.unwrap(msg)
}

func (m *mockGSSContext) Close() error { return nil }
