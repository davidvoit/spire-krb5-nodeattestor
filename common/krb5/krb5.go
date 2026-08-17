package krb5

type AttestationData struct {
	HostName string `json:"hostname"`
}

type Challenge struct {
	// StepToken is the GSS token for the current negotiation step
	StepToken []byte `json:"step_token,omitempty"`

	// WrappedNonce is the wrapped challenge from the server
	WrappedNonce []byte `json:"wrapped_nonce,omitempty"`
}

type ChallengeResponse struct {
	// StepToken is the GSS token for the current negotiation step
	StepToken []byte `json:"step_token,omitempty"`

	// WrappedNonce is the re-wrapped challenge from the agent
	WrappedNonce []byte `json:"wrapped_nonce,omitempty"`
}
