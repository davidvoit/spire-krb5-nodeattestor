package main

import (
	"encoding/json"
	"os"
	"runtime"
	"spire-krb5-nodeattestor/common/krb5"
	"spire-krb5-nodeattestor/common/krb5/gss"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"spire-krb5-nodeattestor/agent/nodeattestor/krb5/dns"
)

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	logger hclog.Logger

	getFQDN          func() (string, error)
	newServerContext func(keytabPath ...string) (gss.GSSContext, error)
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	hostname, err := p.getFQDN()
	if err != nil {
		p.logger.Error("Unable to get fqdn", "error", err)
		return status.Errorf(codes.Internal, "unable to get fqdn: %v", err)
	}

	var keytabPath string
	if runtime.GOOS != "windows" {
		keytabPath = "/etc/krb5.keytab"
		// If the keytab file doesn't exist, fall back to default credentials
		if _, err := os.Stat(keytabPath); err != nil {
			keytabPath = ""
		}
	}

	// Create GSS server context (since NodeAttestor server acts as krb5 client)
	ctx, err := p.newServerContext(keytabPath)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create GSS context: %v", err)
	}
	defer func(ctx gss.GSSContext) {
		_ = ctx.Close()
	}(ctx)

	attestationData := krb5.AttestationData{
		HostName: hostname,
	}

	p.logger.Debug("Starting attestation", "hostname", hostname)

	payload, err := json.Marshal(attestationData)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	}); err != nil {
		return err
	}

	var iteration = 0
	// Limit the number of iterations to prevent infinite loops
	for iteration < 10 {
		iteration++
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		challenge := new(krb5.Challenge)
		if err := json.Unmarshal(req.Challenge, challenge); err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge: %v", err)
		}

		var response krb5.ChallengeResponse

		if len(challenge.StepToken) > 0 {
			outputToken, _, err := ctx.Step(challenge.StepToken)
			if err != nil {
				p.logger.Error("GSS step failed", "error", err)
				return status.Errorf(codes.Internal, "GSS step failed: %v", err)
			}
			response.StepToken = outputToken
		} else if len(challenge.WrappedNonce) > 0 {
			// Unwrap the challenge
			unwrapped, err := ctx.Unwrap(challenge.WrappedNonce)
			if err != nil {
				p.logger.Error("GSS unwrap failed", "error", err)
				return status.Errorf(codes.Internal, "GSS unwrap failed: %v", err)
			}
			// Wrap it back
			wrapped, err := ctx.Wrap(unwrapped)
			if err != nil {
				p.logger.Error("GSS wrap failed", "error", err)
				return status.Errorf(codes.Internal, "GSS wrap failed: %v", err)
			}
			response.WrappedNonce = wrapped
		} else {
			return status.Error(codes.InvalidArgument, "invalid challenge")
		}

		respBytes, err := json.Marshal(response)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to marshal challenge response: %v", err)
		}

		if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
			Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
				ChallengeResponse: respBytes,
			},
		}); err != nil {
			return err
		}

		// If we sent back a wrapped challenge, we are done
		if len(response.WrappedNonce) > 0 {
			p.logger.Info("Agent-Attestation completed", "hostname", hostname)
			return nil
		}
	}

	p.logger.Error("Endless loop detected in attestation, canceling", "hostname", hostname)
	return status.Error(codes.Internal, "Endless loop detected in attestation, canceling")
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func New() *Plugin {
	return &Plugin{
		getFQDN:          dns.GetFQDN,
		newServerContext: gss.NewServerContext,
	}
}

func main() {
	plugin := New()
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
	)
}
