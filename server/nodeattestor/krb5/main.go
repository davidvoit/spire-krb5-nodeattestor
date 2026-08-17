package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"spire-krb5-nodeattestor/common/krb5"
	"spire-krb5-nodeattestor/common/krb5/gss"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *Config

	trustDomain spiffeid.TrustDomain

	logger hclog.Logger

	newClientContext func(targetName string, keytabPath ...string) (gss.GSSContext, error)
}

type Config struct {
	KeytabPath string
}

func MakeAgentID(td spiffeid.TrustDomain, hostName string) (spiffeid.ID, error) {
	agentPath := fmt.Sprintf("/spire/agent/krb5/%s", hostName)
	return spiffeid.FromPath(td, agentPath)
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid trust domain: %v", err)
	}

	if config.KeytabPath != "" {
		if _, err := os.Stat(config.KeytabPath); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "keytab file does not exist: %v", err)
		}
	}

	p.trustDomain = trustDomain
	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(krb5.AttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal attestation data: %v", err)
	}

	if attestationData.HostName == "" {
		return status.Error(codes.InvalidArgument, "missing host in attestation data")
	}

	hostname := strings.ToLower(attestationData.HostName)

	p.logger.Info("Received krb5 node attestation request", "hostname", hostname)

	targetName := fmt.Sprintf("HOST@%s", hostname)

	ctx, err := p.newClientContext(targetName, config.KeytabPath)
	if err != nil {
		p.logger.Error("Unable to create GSS context", "error", err, "target_name", targetName)
		return status.Errorf(codes.Internal, "unable to create GSS context: %v", err)
	}
	defer func(ctx gss.GSSContext) {
		_ = ctx.Close()
	}(ctx)

	// GSS Negotiation
	var inputToken []byte
	for {
		outputToken, done, err := ctx.Step(inputToken)
		if err != nil {
			p.logger.Error("GSS step failed", "error", err)
			return status.Errorf(codes.Internal, "GSS step failed: %v", err)
		}

		if done && len(outputToken) == 0 {
			break
		}

		challenge := krb5.Challenge{
			StepToken: outputToken,
		}
		challengeBytes, err := json.Marshal(challenge)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to marshal challenge: %v", err)
		}

		if err := stream.Send(&nodeattestorv1.AttestResponse{
			Response: &nodeattestorv1.AttestResponse_Challenge{
				Challenge: challengeBytes,
			},
		}); err != nil {
			return err
		}

		if done {
			break
		}

		resp, err := stream.Recv()
		if err != nil {
			return err
		}

		challengeResp := new(krb5.ChallengeResponse)
		if err := json.Unmarshal(resp.GetChallengeResponse(), challengeResp); err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge response: %v", err)
		}
		inputToken = challengeResp.StepToken
	}

	// GSS session established. We generate a random nonce and do a wrap/unwrap/wrap round trip
	randomNonce := make([]byte, 32)
	if _, err := rand.Read(randomNonce); err != nil {
		return status.Errorf(codes.Internal, "unable to generate random challenge: %v", err)
	}

	wrappedNonce, err := ctx.Wrap(randomNonce)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to wrap challenge: %v", err)
	}

	challenge := krb5.Challenge{
		WrappedNonce: wrappedNonce,
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return err
	}

	resp, err := stream.Recv()
	if err != nil {
		return err
	}

	challengeResp := new(krb5.ChallengeResponse)
	if err := json.Unmarshal(resp.GetChallengeResponse(), challengeResp); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge response: %v", err)
	}

	unwrappedResponse, err := ctx.Unwrap(challengeResp.WrappedNonce)
	if err != nil {
		p.logger.Error("Unable to unwrap challenge response", "error", err)
		return status.Errorf(codes.Internal, "unable to unwrap challenge response: %v", err)
	}

	if subtle.ConstantTimeCompare(randomNonce, unwrappedResponse) != 1 {
		p.logger.Error("Challenge response verification failed")
		return status.Error(codes.PermissionDenied, "challenge response verification failed")
	}

	agentID, err := MakeAgentID(p.trustDomain, hostname)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create agent ID: %v", err)
	}

	p.logger.Info("Node attestation successful", "agent_id", agentID.String(), "hostname", hostname)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId: agentID.String(),
				SelectorValues: []string{
					fmt.Sprintf("hostname:%s", hostname),
				},
			},
		},
	})
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func New() *Plugin {
	return &Plugin{
		newClientContext: gss.NewClientContext,
	}
}

func main() {
	plugin := New()
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
