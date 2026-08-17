//go:build windows

package gss

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	secur32                   = windows.NewLazySystemDLL("secur32.dll")
	acquireCredentialsHandle  = secur32.NewProc("AcquireCredentialsHandleW")
	freeCredentialsHandle     = secur32.NewProc("FreeCredentialsHandle")
	initializeSecurityContext = secur32.NewProc("InitializeSecurityContextW")
	acceptSecurityContext     = secur32.NewProc("AcceptSecurityContext")
	deleteSecurityContext     = secur32.NewProc("DeleteSecurityContext")
	encryptMessage            = secur32.NewProc("EncryptMessage")
	decryptMessage            = secur32.NewProc("DecryptMessage")
	freeContextBuffer         = secur32.NewProc("FreeContextBuffer")
	queryContextAttributes    = secur32.NewProc("QueryContextAttributesW")
	completeAuthToken         = secur32.NewProc("CompleteAuthToken")

	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	formatMessage = kernel32.NewProc("FormatMessageW")
)

const (
	SECPKG_CRED_INBOUND  = 1
	SECPKG_CRED_OUTBOUND = 2

	ISC_REQ_MUTUAL_AUTH     = 0x00000002
	ISC_REQ_REPLAY_DETECT   = 0x00000004
	ISC_REQ_SEQUENCE_DETECT = 0x00000008
	ISC_REQ_CONFIDENTIALITY = 0x00000010
	ISC_REQ_ALLOCATE_MEMORY = 0x00000100
	ISC_REQ_INTEGRITY       = 0x00010000

	ASC_REQ_REPLAY_DETECT   = 0x00000004
	ASC_REQ_SEQUENCE_DETECT = 0x00000008
	ASC_REQ_CONFIDENTIALITY = 0x00000010
	ASC_REQ_ALLOCATE_MEMORY = 0x00000100
	ASC_REQ_INTEGRITY       = 0x00020000

	SECBUFFER_VERSION = 0
	SECBUFFER_DATA    = 1
	SECBUFFER_TOKEN   = 2
	SECBUFFER_PADDING = 9
	SECBUFFER_STREAM  = 10

	SEC_E_OK                    = 0x00000000
	SEC_I_CONTINUE_NEEDED       = 0x00090312
	SEC_I_COMPLETE_NEEDED       = 0x00090313
	SEC_I_COMPLETE_AND_CONTINUE = 0x00090314

	SECPKG_ATTR_SIZES = 0
)

type SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   unsafe.Pointer
}

type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  unsafe.Pointer
}

type SecPkgContext_Sizes struct {
	cbMaxToken        uint32
	cbMaxSignature    uint32
	cbBlockSize       uint32
	cbSecurityTrailer uint32
}

type windowsGSSContext struct {
	credHandle SecHandle
	ctxHandle  SecHandle
	hasCtx     bool
	targetName *uint16
}

func newClientContext(targetName, _ string) (GSSContext, error) {
	pkgName := "Kerberos"

	var credHandle SecHandle
	packagePtr, err := windows.UTF16PtrFromString(pkgName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert package name to UTF16: %w", err)
	}

	ret, _, _ := acquireCredentialsHandle.Call(
		0,
		uintptr(unsafe.Pointer(packagePtr)),
		SECPKG_CRED_OUTBOUND,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&credHandle)),
		0)

	if ret != SEC_E_OK {
		return nil, fmt.Errorf("AcquireCredentialsHandle: %w", sspiError(ret))
	}

	// SSPI expects service/host format instead of GSSAPI's service@host
	sspiTargetName := strings.Replace(targetName, "@", "/", 1)
	uTargetName, err := windows.UTF16PtrFromString(sspiTargetName)
	if err != nil {
		_, _, _ = freeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))
		return nil, fmt.Errorf("failed to convert target name to UTF16: %w", err)
	}

	return &windowsGSSContext{
		credHandle: credHandle,
		targetName: uTargetName,
	}, nil
}

func newServerContext(_ string) (GSSContext, error) {
	pkgName := "Kerberos"

	pkg, err := windows.UTF16PtrFromString(pkgName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert package name to UTF16: %w", err)
	}

	var credHandle SecHandle
	ret, _, _ := acquireCredentialsHandle.Call(
		0,
		uintptr(unsafe.Pointer(pkg)),
		SECPKG_CRED_INBOUND,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&credHandle)),
		0)

	if ret != SEC_E_OK {
		return nil, fmt.Errorf("AcquireCredentialsHandle: %w", sspiError(ret))
	}

	return &windowsGSSContext{
		credHandle: credHandle,
	}, nil
}

func (c *windowsGSSContext) Step(inputToken []byte) ([]byte, bool, error) {
	var inBufDesc SecBufferDesc
	var inBuf SecBuffer
	if len(inputToken) > 0 {
		inBuf.cbBuffer = uint32(len(inputToken))
		inBuf.BufferType = SECBUFFER_TOKEN
		inBuf.pvBuffer = unsafe.Pointer(&inputToken[0])
		inBufDesc.ulVersion = SECBUFFER_VERSION
		inBufDesc.cBuffers = 1
		inBufDesc.pBuffers = unsafe.Pointer(&inBuf)
	}

	var outBufDesc SecBufferDesc
	var outBuf SecBuffer
	outBuf.cbBuffer = 0
	outBuf.BufferType = SECBUFFER_TOKEN
	outBuf.pvBuffer = nil
	outBufDesc.ulVersion = SECBUFFER_VERSION
	outBufDesc.cBuffers = 1
	outBufDesc.pBuffers = unsafe.Pointer(&outBuf)

	var ret uintptr
	var outAttrs uint32
	var expiry windows.Filetime

	if c.targetName != nil {
		var ctxIn uintptr
		if c.hasCtx {
			ctxIn = uintptr(unsafe.Pointer(&c.ctxHandle))
		}

		ret, _, _ = initializeSecurityContext.Call(
			uintptr(unsafe.Pointer(&c.credHandle)),
			ctxIn,
			uintptr(unsafe.Pointer(c.targetName)),
			ISC_REQ_CONFIDENTIALITY|ISC_REQ_INTEGRITY|ISC_REQ_MUTUAL_AUTH|ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|ISC_REQ_ALLOCATE_MEMORY,
			0, 0,
			uintptr(unsafe.Pointer(&inBufDesc)),
			0,
			uintptr(unsafe.Pointer(&c.ctxHandle)),
			uintptr(unsafe.Pointer(&outBufDesc)),
			uintptr(unsafe.Pointer(&outAttrs)),
			uintptr(unsafe.Pointer(&expiry)))
	} else {
		var ctxIn uintptr
		if c.hasCtx {
			ctxIn = uintptr(unsafe.Pointer(&c.ctxHandle))
		}

		ret, _, _ = acceptSecurityContext.Call(
			uintptr(unsafe.Pointer(&c.credHandle)),
			ctxIn,
			uintptr(unsafe.Pointer(&inBufDesc)),
			ASC_REQ_CONFIDENTIALITY|ASC_REQ_INTEGRITY|ASC_REQ_SEQUENCE_DETECT|ASC_REQ_REPLAY_DETECT|ASC_REQ_ALLOCATE_MEMORY,
			0,
			uintptr(unsafe.Pointer(&c.ctxHandle)),
			uintptr(unsafe.Pointer(&outBufDesc)),
			uintptr(unsafe.Pointer(&outAttrs)),
			uintptr(unsafe.Pointer(&expiry)))
	}

	runtime.KeepAlive(inBufDesc)
	runtime.KeepAlive(inBuf)
	runtime.KeepAlive(inputToken)
	runtime.KeepAlive(outBufDesc)
	runtime.KeepAlive(outBuf)

	c.hasCtx = true

	if ret != SEC_E_OK && ret != SEC_I_CONTINUE_NEEDED && ret != SEC_I_COMPLETE_NEEDED && ret != SEC_I_COMPLETE_AND_CONTINUE {
		if outBuf.pvBuffer != nil {
			_, _, _ = freeContextBuffer.Call(uintptr(outBuf.pvBuffer))
		}
		return nil, false, fmt.Errorf("SSPI step: %w", sspiError(ret))
	}

	if ret == SEC_I_COMPLETE_NEEDED || ret == SEC_I_COMPLETE_AND_CONTINUE {
		retComplete, _, _ := completeAuthToken.Call(uintptr(unsafe.Pointer(&c.ctxHandle)), uintptr(unsafe.Pointer(&outBufDesc)))
		if retComplete != SEC_E_OK {
			if outBuf.pvBuffer != nil {
				_, _, _ = freeContextBuffer.Call(uintptr(outBuf.pvBuffer))
			}
			return nil, false, fmt.Errorf("CompleteAuthToken: %w", sspiError(retComplete))
		}
	}

	var outputToken []byte
	if outBuf.pvBuffer != nil {
		outputToken = make([]byte, outBuf.cbBuffer)
		copy(outputToken, unsafe.Slice((*byte)(outBuf.pvBuffer), outBuf.cbBuffer))
		_, _, _ = freeContextBuffer.Call(uintptr(outBuf.pvBuffer))
	}

	return outputToken, ret == SEC_E_OK || ret == SEC_I_COMPLETE_NEEDED, nil
}

func (c *windowsGSSContext) Wrap(msg []byte) ([]byte, error) {
	var sizes SecPkgContext_Sizes
	ret, _, _ := queryContextAttributes.Call(
		uintptr(unsafe.Pointer(&c.ctxHandle)),
		SECPKG_ATTR_SIZES,
		uintptr(unsafe.Pointer(&sizes)))
	if ret != SEC_E_OK {
		return nil, fmt.Errorf("QueryContextAttributes: %w", sspiError(ret))
	}

	// For GSSAPI compatibility, we use 3 buffers:
	// 1. SECBUFFER_TOKEN (Header)
	// 2. SECBUFFER_DATA  (Payload)
	// 3. SECBUFFER_PADDING (Trailer)

	header := make([]byte, sizes.cbSecurityTrailer)
	data := make([]byte, len(msg))
	copy(data, msg)
	padding := make([]byte, sizes.cbBlockSize) // Typically not used for Kerberos GSSAPI style but good to have

	bufs := []SecBuffer{
		{cbBuffer: uint32(len(header)), BufferType: SECBUFFER_TOKEN, pvBuffer: unsafe.Pointer(&header[0])},
		{cbBuffer: uint32(len(data)), BufferType: SECBUFFER_DATA, pvBuffer: unsafe.Pointer(&data[0])},
		{cbBuffer: uint32(len(padding)), BufferType: SECBUFFER_PADDING, pvBuffer: unsafe.Pointer(&padding[0])},
	}

	desc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  uint32(len(bufs)),
		pBuffers:  unsafe.Pointer(&bufs[0]),
	}

	ret, _, _ = encryptMessage.Call(
		uintptr(unsafe.Pointer(&c.ctxHandle)),
		0,
		uintptr(unsafe.Pointer(&desc)),
		0)

	if ret != SEC_E_OK {
		return nil, fmt.Errorf("EncryptMessage: %w", sspiError(ret))
	}

	runtime.KeepAlive(desc)
	runtime.KeepAlive(bufs)
	runtime.KeepAlive(header)
	runtime.KeepAlive(data)
	runtime.KeepAlive(padding)

	// GSSAPI wrap token is the concatenation of Header + Data + Padding (Trailer)
	res := append(header[:bufs[0].cbBuffer], data[:bufs[1].cbBuffer]...)
	res = append(res, padding[:bufs[2].cbBuffer]...)

	return res, nil
}

func (c *windowsGSSContext) Unwrap(msg []byte) ([]byte, error) {
	// For GSSAPI compatibility, we use SECBUFFER_STREAM
	// The message contains both the header, data and trailer.

	if len(msg) == 0 {
		return nil, fmt.Errorf("empty message")
	}

	data := make([]byte, len(msg))
	copy(data, msg)

	bufs := []SecBuffer{
		{cbBuffer: uint32(len(data)), BufferType: SECBUFFER_STREAM, pvBuffer: unsafe.Pointer(&data[0])},
		{cbBuffer: 0, BufferType: SECBUFFER_DATA, pvBuffer: nil},
	}

	desc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  uint32(len(bufs)),
		pBuffers:  unsafe.Pointer(&bufs[0]),
	}

	var qop uint32
	ret, _, _ := decryptMessage.Call(
		uintptr(unsafe.Pointer(&c.ctxHandle)),
		uintptr(unsafe.Pointer(&desc)),
		0,
		uintptr(unsafe.Pointer(&qop)))

	if ret != SEC_E_OK {
		return nil, fmt.Errorf("DecryptMessage: %w", sspiError(ret))
	}

	runtime.KeepAlive(desc)
	runtime.KeepAlive(bufs)
	runtime.KeepAlive(data)

	// The SECBUFFER_DATA buffer now points to the decrypted data within the SECBUFFER_STREAM
	// Note: DecryptMessage decrypts in-place.
	decrypted := make([]byte, bufs[1].cbBuffer)
	copy(decrypted, unsafe.Slice((*byte)(bufs[1].pvBuffer), bufs[1].cbBuffer))
	return decrypted, nil
}

func (c *windowsGSSContext) Close() error {
	if c.hasCtx {
		_, _, _ = deleteSecurityContext.Call(uintptr(unsafe.Pointer(&c.ctxHandle)))
	}
	_, _, _ = freeCredentialsHandle.Call(uintptr(unsafe.Pointer(&c.credHandle)))
	return nil
}

// sspiError returns a human-readable error for an SSPI HRESULT code.
// It calls FormatMessageW with FORMAT_MESSAGE_FROM_SYSTEM so Windows looks up
// the message text from its own message tables (covers all SEC_E_* / SEC_I_* codes).
func sspiError(code uintptr) error {
	const (
		FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
		FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
		FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
	)
	var msgPtr *uint16
	ret, _, _ := formatMessage.Call(
		FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_ALLOCATE_BUFFER,
		0,
		code,
		0,
		uintptr(unsafe.Pointer(&msgPtr)),
		0, 0,
	)
	if ret > 0 && msgPtr != nil {
		defer func(hmem windows.Handle) {
			_, _ = windows.LocalFree(hmem)
		}(windows.Handle(unsafe.Pointer(msgPtr)))
		msg := strings.TrimRight(windows.UTF16PtrToString(msgPtr), "\r\n ")
		return fmt.Errorf("%s (0x%x)", msg, code)
	}
	return fmt.Errorf("SSPI error 0x%x", code)
}
