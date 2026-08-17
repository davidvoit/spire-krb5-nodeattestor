package krb5test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AgentServerStreamHandler = func(payloadOrChallengeResponse []byte) (challenge []byte, err error)

type AgentServerStreamBuilder struct {
	handlers []AgentServerStreamHandler
}

func NewAgentServerStream() *AgentServerStreamBuilder {
	return &AgentServerStreamBuilder{}
}

func (b *AgentServerStreamBuilder) Handle(handler AgentServerStreamHandler) *AgentServerStreamBuilder {
	clone := *b
	clone.handlers = append(append([]AgentServerStreamHandler{}, b.handlers...), handler)
	return &clone
}

func (b *AgentServerStreamBuilder) ExpectThenChallenge(wantSend, challenge []byte) *AgentServerStreamBuilder {
	return b.Handle(func(actual []byte) ([]byte, error) {
		if !bytes.Equal(actual, wantSend) {
			return nil, status.Errorf(codes.InvalidArgument, "expected payload %q; got %q", wantSend, actual)
		}
		return challenge, nil
	})
}

func (b *AgentServerStreamBuilder) IgnoreThenChallenge(challenge []byte) *AgentServerStreamBuilder {
	return b.Handle(func([]byte) ([]byte, error) { return challenge, nil })
}

func (b *AgentServerStreamBuilder) ExpectAndBuild(wantSend []byte) *AgentServerStream {
	return b.ExpectThenChallenge(wantSend, nil).Build()
}

func (b *AgentServerStreamBuilder) FailAndBuild(err error) *AgentServerStream {
	return b.Handle(func([]byte) ([]byte, error) { return nil, err }).Build()
}

func (b *AgentServerStreamBuilder) Build() *AgentServerStream {
	return &AgentServerStream{handlers: append([]AgentServerStreamHandler{}, b.handlers...), ctx: context.Background()}
}

type AgentServerStream struct {
	T        *testing.T
	handlers []AgentServerStreamHandler
	pending  []byte
	ctx      context.Context
}

func (s *AgentServerStream) WithTesting(t *testing.T) *AgentServerStream {
	s.T = t
	return s
}

func (s *AgentServerStream) Send(msg *agentv1.PayloadOrChallengeResponse) error {
	if len(s.handlers) == 0 {
		return errors.New("stream received unexpected Send")
	}
	var payload []byte
	switch d := msg.Data.(type) {
	case *agentv1.PayloadOrChallengeResponse_Payload:
		payload = d.Payload
	case *agentv1.PayloadOrChallengeResponse_ChallengeResponse:
		payload = d.ChallengeResponse
	}
	handler := s.handlers[0]
	s.handlers = s.handlers[1:]
	challenge, err := handler(payload)
	if err != nil {
		return err
	}
	s.pending = challenge
	return nil
}

func (s *AgentServerStream) Recv() (*agentv1.Challenge, error) {
	if s.pending == nil {
		return nil, io.EOF
	}
	challenge := s.pending
	s.pending = nil
	return &agentv1.Challenge{Challenge: challenge}, nil
}

func (s *AgentServerStream) Context() context.Context     { return s.ctx }
func (s *AgentServerStream) SendHeader(metadata.MD) error { return nil }
func (s *AgentServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *AgentServerStream) SetTrailer(metadata.MD)       {}
func (s *AgentServerStream) SendMsg(any) error            { return nil }
func (s *AgentServerStream) RecvMsg(any) error            { return nil }
