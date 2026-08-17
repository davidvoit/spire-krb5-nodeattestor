package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"spire-krb5-nodeattestor/common/krb5"
	"spire-krb5-nodeattestor/common/krb5/gss"
	gssmock "spire-krb5-nodeattestor/common/krb5/gss/mock"
	krb5test "spire-krb5-nodeattestor/common/krb5/test"
)

var testLogger = hclog.New(&hclog.LoggerOptions{Name: "krb5-server-test", Level: hclog.Debug})

const testTrustDomain = "example.org"
const testHostname = "test.example.com"

func mustTrustDomain(s string) spiffeid.TrustDomain {
	td, _ := spiffeid.TrustDomainFromString(s)
	return td
}

func TestAttest_Good(t *testing.T) {
	serverHostInitiateToken := []byte("initiate-host/test.example.com")
	agentAcceptToken := []byte("accept-host/test.example.com")
	serverInitiateComplete := []byte("initiate-complete")
	agentAcceptComplete := []byte("accept-complete")
	fixedNonce := []byte("fixed-nonce")
	wrappedNonce := []byte("wrapped-nonce")

	agentHostname, _ := json.Marshal(krb5.AttestationData{HostName: testHostname})
	stepServerInitiate, _ := json.Marshal(krb5.Challenge{StepToken: serverHostInitiateToken})
	stepAgentAccept, _ := json.Marshal(krb5.ChallengeResponse{StepToken: agentAcceptToken})
	stepServerComplete, _ := json.Marshal(krb5.Challenge{StepToken: serverInitiateComplete})
	stepAgentComplete, _ := json.Marshal(krb5.ChallengeResponse{StepToken: agentAcceptComplete})
	nonceChallenge, _ := json.Marshal(krb5.Challenge{WrappedNonce: wrappedNonce})
	nonceResponse, _ := json.Marshal(krb5.ChallengeResponse{WrappedNonce: wrappedNonce})

	expectedAgentID, _ := MakeAgentID(mustTrustDomain(testTrustDomain), testHostname)

	_, newCtx := gssmock.NewGSSContext().
		ExpectThenStep(nil, serverHostInitiateToken, false).
		ExpectThenStep(agentAcceptToken, serverInitiateComplete, false).
		ExpectThenStep(agentAcceptComplete, nil, true).
		ExpectAndWrap(fixedNonce, wrappedNonce).
		ExpectAndUnwrap(wrappedNonce, fixedNonce).
		BuildClient()

	stream := krb5test.NewServerAttestStream().
		ExpectPayloadThenChallenge(agentHostname, stepServerInitiate).
		ExpectChallengeThenRespond(stepAgentAccept, stepServerComplete).
		ExpectChallengeThenRespond(stepAgentComplete, nonceChallenge).
		ExpectFinalAndBuild(nonceResponse, expectedAgentID.String(), []string{"hostname:" + testHostname}).
		WithTesting(t)

	plugin := &Plugin{
		logger:           testLogger,
		trustDomain:      mustTrustDomain(testTrustDomain),
		config:           &Config{},
		newClientContext: newCtx,
		generateNonce:    func() ([]byte, error) { return fixedNonce, nil },
	}

	if err := plugin.Attest(stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAttest_HostNotFoundError(t *testing.T) {
	agentHostname, _ := json.Marshal(krb5.AttestationData{HostName: testHostname})

	gssErr := errors.New("no spn HOST@test.example.com")

	stream := krb5test.NewServerAttestStream().
		WithPayload(agentHostname).
		Build().
		WithTesting(t)

	plugin := &Plugin{
		logger:           testLogger,
		trustDomain:      mustTrustDomain(testTrustDomain),
		config:           &Config{},
		newClientContext: func(string, ...string) (gss.GSSContext, error) { return nil, gssErr },
	}

	err := plugin.Attest(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAttest_GSSStepError(t *testing.T) {
	serverHostInitiateToken := []byte("initiate-host/test.example.com")

	agentHostname, _ := json.Marshal(krb5.AttestationData{HostName: testHostname})
	stepServerInitiate, _ := json.Marshal(krb5.Challenge{StepToken: serverHostInitiateToken})
	stepAgentAccept, _ := json.Marshal(krb5.ChallengeResponse{StepToken: []byte("accept-host/test.example.com")})

	_, newCtx := gssmock.NewGSSContext().
		ExpectThenStep(nil, serverHostInitiateToken, false).
		FailStep(errors.New("step failed")).
		BuildClient()

	stream := krb5test.NewServerAttestStream().
		ExpectPayloadThenChallenge(agentHostname, stepServerInitiate).
		ExpectChallengeThenRespond(stepAgentAccept, nil).
		Build().
		WithTesting(t)

	plugin := &Plugin{
		logger:           testLogger,
		trustDomain:      mustTrustDomain(testTrustDomain),
		config:           &Config{},
		newClientContext: newCtx,
	}

	err := plugin.Attest(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
