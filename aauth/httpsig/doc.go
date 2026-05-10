// Package httpsig implements HTTP Message Signatures per RFC 9421.
//
// # Overview
//
// HTTP Message Signatures provide a mechanism for digitally signing HTTP
// messages, enabling authentication, integrity protection, and non-repudiation.
// This package implements the signature creation and verification mechanisms
// required by the AAuth protocol.
//
// # Covered Components
//
// The signature covers specific components of the HTTP message:
//
//   - @method: The HTTP method (GET, POST, etc.)
//   - @target-uri: The full request target URI
//   - @authority: The host from the request
//   - @path: The path portion of the request target
//   - @query: The query string
//   - Standard headers: Any HTTP headers included in the signature base
//
// # Usage Example
//
//	// Create a signer
//	signer, err := httpsig.NewSigner(httpsig.SignerOptions{
//	    PrivateKey: privateKey,
//	    KeyID:      "my-key-1",
//	    Algorithm:  "ecdsa-p256-sha256",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Sign a request
//	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
//	if err := signer.Sign(req); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify a request
//	verifier := httpsig.NewVerifier(httpsig.VerifierOptions{
//	    PublicKey: publicKey,
//	    KeyID:     "my-key-1",
//	})
//	result, err := verifier.Verify(req)
//
// # References
//
//   - RFC 9421: https://www.rfc-editor.org/rfc/rfc9421
//   - RFC 9530 (Content-Digest): https://www.rfc-editor.org/rfc/rfc9530
package httpsig
