package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"

	"spire-krb5-nodeattestor/common/krb5"
	"spire-krb5-nodeattestor/common/krb5/gss"
	gssmock "spire-krb5-nodeattestor/common/krb5/gss/mock"
	krb5test "spire-krb5-nodeattestor/common/krb5/test"
)

var testLogger = hclog.New(&hclog.LoggerOptions{Name: "krb5-test", Level: hclog.Debug})

func TestAidAttestation_Good(t *testing.T) {
	serverHostInitiateToken := []byte("initiate-host/test.example.com")
	agentAcceptToken := []byte("accept-host/test.example.com")
	serverInitiateComplete := []byte("initiate-complete")
	agentAcceptComplete := []byte("accept-complete")
	wrappedNonce := []byte("wrapped-nonce")
	plain := []byte("plain-nonce")
	rewrappedNonce := []byte("rewrapped-nonce")

	sendHostname, _ := json.Marshal(krb5.AttestationData{HostName: "test.example.com"})
	stepServerInitiate, _ := json.Marshal(krb5.Challenge{StepToken: serverHostInitiateToken})
	stepAgentAccept, _ := json.Marshal(krb5.ChallengeResponse{StepToken: agentAcceptToken})
	stepServerComplete, _ := json.Marshal(krb5.Challenge{StepToken: serverInitiateComplete})
	stepAgentComplete, _ := json.Marshal(krb5.ChallengeResponse{StepToken: agentAcceptComplete})
	nonceChallenge, _ := json.Marshal(krb5.Challenge{WrappedNonce: wrappedNonce})
	nonceResponse, _ := json.Marshal(krb5.ChallengeResponse{WrappedNonce: rewrappedNonce})

	_, newCtx := gssmock.NewGSSContext().
		ExpectThenStep(serverHostInitiateToken, agentAcceptToken, false).
		ExpectThenStep(serverInitiateComplete, agentAcceptComplete, true).
		ExpectAndUnwrap(wrappedNonce, plain).
		ExpectAndWrap(plain, rewrappedNonce).
		Build()

	stream := krb5test.NewAgentServerStream().
		ExpectThenChallenge(sendHostname, stepServerInitiate).
		ExpectThenChallenge(stepAgentAccept, stepServerComplete).
		ExpectThenChallenge(stepAgentComplete, nonceChallenge).
		ExpectAndBuild(nonceResponse).
		WithTesting(t)

	plugin := &Plugin{
		logger:           testLogger,
		getFQDN:          func() (string, error) { return "test.example.com", nil },
		newServerContext: newCtx,
	}

	if err := plugin.AidAttestation(stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAidAttestation_GSSError(t *testing.T) {
	serverHostInitiateToken := []byte("initiate-host/test.example.com")

	sendHostname, _ := json.Marshal(krb5.AttestationData{HostName: "test.example.com"})
	stepServerInitiate, _ := json.Marshal(krb5.Challenge{StepToken: serverHostInitiateToken})

	_, newCtx := gssmock.NewGSSContext().
		FailStep(errors.New("step failed")).
		Build()

	stream := krb5test.NewAgentServerStream().
		ExpectThenChallenge(sendHostname, stepServerInitiate).
		Build().
		WithTesting(t)

	plugin := &Plugin{
		logger:           testLogger,
		getFQDN:          func() (string, error) { return "test.example.com", nil },
		newServerContext: newCtx,
	}

	err := plugin.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAidAttestation_GSSContextError(t *testing.T) {
	stream := krb5test.NewAgentServerStream().
		Build().
		WithTesting(t)

	plugin := &Plugin{
		logger:  testLogger,
		getFQDN: func() (string, error) { return "test.example.com", nil },
		newServerContext: func(...string) (gss.GSSContext, error) {
			return nil, errors.New("Can't accept connection for HOST/test.example.com")
		},
	}

	err := plugin.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
