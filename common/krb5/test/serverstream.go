package krb5test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ServerAttestStreamBuilder struct {
	initialPayload []byte
	recvQueue      [][]byte
	sendHandlers   []func(*serverv1.AttestResponse) error
}

func NewServerAttestStream() *ServerAttestStreamBuilder {
	return &ServerAttestStreamBuilder{}
}

// WithPayload sets the initial payload returned on the first Recv without expecting any Send.
func (b *ServerAttestStreamBuilder) WithPayload(agentPayload []byte) *ServerAttestStreamBuilder {
	clone := b.clone()
	clone.initialPayload = agentPayload
	return clone
}

func (b *ServerAttestStreamBuilder) clone() *ServerAttestStreamBuilder {
	return &ServerAttestStreamBuilder{
		initialPayload: b.initialPayload,
		recvQueue:      append([][]byte{}, b.recvQueue...),
		sendHandlers:   append([]func(*serverv1.AttestResponse) error{}, b.sendHandlers...),
	}
}

func (b *ServerAttestStreamBuilder) ExpectPayloadThenChallenge(agentPayload, wantChallenge []byte) *ServerAttestStreamBuilder {
	clone := b.clone()
	clone.initialPayload = agentPayload
	clone.sendHandlers = append(clone.sendHandlers, expectChallenge(wantChallenge))
	return clone
}

func (b *ServerAttestStreamBuilder) ExpectChallengeThenRespond(agentResponse, wantChallenge []byte) *ServerAttestStreamBuilder {
	clone := b.clone()
	clone.recvQueue = append(clone.recvQueue, agentResponse)
	clone.sendHandlers = append(clone.sendHandlers, expectChallenge(wantChallenge))
	return clone
}

func (b *ServerAttestStreamBuilder) ExpectFinalAndBuild(finalAgentResponse []byte, wantSpiffeID string, wantSelectors []string) *ServerAttestStream {
	clone := b.clone()
	clone.recvQueue = append(clone.recvQueue, finalAgentResponse)
	clone.sendHandlers = append(clone.sendHandlers, func(resp *serverv1.AttestResponse) error {
		attrs := resp.GetAgentAttributes()
		if attrs == nil {
			return errors.New("expected AgentAttributes, got nil")
		}
		if attrs.SpiffeId != wantSpiffeID {
			return status.Errorf(codes.InvalidArgument, "expected spiffe ID %q; got %q", wantSpiffeID, attrs.SpiffeId)
		}
		if wantSelectors != nil && !stringSliceEqual(attrs.SelectorValues, wantSelectors) {
			return status.Errorf(codes.InvalidArgument, "expected selectors %v; got %v", wantSelectors, attrs.SelectorValues)
		}
		return nil
	})
	return clone.Build()
}

func (b *ServerAttestStreamBuilder) FailAndBuild(err error) *ServerAttestStream {
	clone := b.clone()
	clone.sendHandlers = append(clone.sendHandlers, func(*serverv1.AttestResponse) error { return err })
	return clone.Build()
}

func (b *ServerAttestStreamBuilder) Build() *ServerAttestStream {
	return &ServerAttestStream{
		ctx:            context.Background(),
		initialPayload: b.initialPayload,
		recvQueue:      append([][]byte{}, b.recvQueue...),
		sendHandlers:   append([]func(*serverv1.AttestResponse) error{}, b.sendHandlers...),
	}
}

type ServerAttestStream struct {
	T              *testing.T
	ctx            context.Context
	initialPayload []byte
	recvQueue      [][]byte
	sendHandlers   []func(*serverv1.AttestResponse) error
	recvIdx        int
	sendIdx        int
}

func (s *ServerAttestStream) WithTesting(t *testing.T) *ServerAttestStream {
	s.T = t
	return s
}

func (s *ServerAttestStream) Recv() (*serverv1.AttestRequest, error) {
	defer func() { s.recvIdx++ }()
	if s.recvIdx == 0 {
		return &serverv1.AttestRequest{Request: &serverv1.AttestRequest_Payload{Payload: s.initialPayload}}, nil
	}
	queueIdx := s.recvIdx - 1
	if queueIdx >= len(s.recvQueue) {
		return nil, errors.New("stream received unexpected Recv")
	}
	return &serverv1.AttestRequest{
		Request: &serverv1.AttestRequest_ChallengeResponse{ChallengeResponse: s.recvQueue[queueIdx]},
	}, nil
}

func (s *ServerAttestStream) Send(resp *serverv1.AttestResponse) error {
	if s.sendIdx >= len(s.sendHandlers) {
		return errors.New("stream received unexpected Send")
	}
	handler := s.sendHandlers[s.sendIdx]
	s.sendIdx++
	return handler(resp)
}

func (s *ServerAttestStream) Context() context.Context     { return s.ctx }
func (s *ServerAttestStream) SendHeader(metadata.MD) error { return nil }
func (s *ServerAttestStream) SetHeader(metadata.MD) error  { return nil }
func (s *ServerAttestStream) SetTrailer(metadata.MD)       {}
func (s *ServerAttestStream) SendMsg(any) error            { return nil }
func (s *ServerAttestStream) RecvMsg(any) error            { return nil }

func expectChallenge(wantChallenge []byte) func(*serverv1.AttestResponse) error {
	return func(resp *serverv1.AttestResponse) error {
		got := resp.GetChallenge()
		if !bytes.Equal(got, wantChallenge) {
			return status.Errorf(codes.InvalidArgument, "expected challenge %q; got %q", wantChallenge, got)
		}
		return nil
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
