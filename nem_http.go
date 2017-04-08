package winrm

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/masterzen/winrm/soap"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
)

// NegotiateEncryptedTransport uses a security context established using NTLM to exchange encrypted HTTP payloads
type NegotiateEncryptedTransport struct {
	// Client NTLM session used to establish security context for the HTTP session
	ntlmSession ntlm.ClientSession
	// Encrypted NTLM requires the sequence number to be tracked to provide session integrity
	sequenceNumber uint32
	// Authentication once estalished is persisted for duration of connection. See https://msdn.microsoft.com/en-us/library/cc236621.aspx
	authenticated bool
	// WinRM client containing credentials credentials used for current POST request.
	client *Client
	// Client Request is the default HTTP transport which we inherit from
	httpTransporter clientRequest
	// The original HTTP transport used by ClientRequest that this object has replaced to insert itself into the call path
	http.RoundTripper
}

const authSchemeNegotiate = "Negotiate"
const multipartBoundary = "Encrypted Boundary"
const mimeMediaTypeMultipartEncrypted = "multipart/encrypted"
const mimeMediaTypeSPNEGOEncrypted = "application/HTTP-SPNEGO-session-encrypted"
const mimeMediaTypeOctetStream = "application/octet-stream"

const CRLF = "\r\n"

func (t NegotiateEncryptedTransport) Transport(endpoint *Endpoint) (err error) {
	// Start by initialising the base HTTP transporter
	if err = t.httpTransporter.Transport(endpoint); err != nil {
		return err
	}

	// Initialise the NTLM context
	mode := ntlm.Mode{Stream: true, Confidentiality: true}
	if t.ntlmSession, err = ntlm.CreateClientSession(ntlm.Version2, mode); err != nil {
		return err
	}

	// Finally inject ourselves into the http.RoundTrip hierarchy to intercept messages from the HTTP Transporter
	t.RoundTripper = t.httpTransporter.transport
	t.httpTransporter.transport = t

	return nil
}

func (t NegotiateEncryptedTransport) Post(client *Client, request *soap.SoapMessage) (string, error) {
	// Store reference to the client who we are making this post request on behalf of
	t.client = client

	// Call the default HTTP transport. This will in turn involve our RoundTrip method which we have injected into the call path
	return t.httpTransporter.Post(client, request)
}

// RoundTrip sends the request to the server, handling the NTLM authentication and message encryption
func (t NegotiateEncryptedTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {

	// Alias common fields
	ns := t.ntlmSession
	rt := t.RoundTripper

	// Check that client  has been properly initialised
	if ns == nil || rt == nil {
		return nil, errors.New("NegotiateEncryptedTransport: Uninitialised transporter context")
	}

	// Remove any authorization headers. This implementation manages authorization using Negotiate method
	req.Header.Del("Authorization")

	// Save a copy of the request body and content type for later use
	contentType := req.Header.Get("Content-Type")
	body := bytes.Buffer{}
	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			return nil, err
		}

		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
		req.ContentLength = int64(body.Len())
	}

reauthenticate:

	// If transport is not already authenticated, attempt to authenticate now
	if !t.authenticated {

		// Generated the initial negotiate message
		negotiate, err := ns.GenerateNegotiateMessage()
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", authSchemeNegotiate+" "+base64.StdEncoding.EncodeToString(negotiate.Bytes()))

		// We expect 401 response. If we receive any other type of error, return
		if res, err = rt.RoundTrip(req); err != nil || res.StatusCode != http.StatusUnauthorized {
			return res, err
		}

		// Read challenge in the Www-Authenticate header
		challengeBase64, err := getAuthenticationChallenge(res, authSchemeNegotiate)
		if err != nil {
			return res, fmt.Errorf("Unable to secure connection: %v", err)
		}

		// Decode and parse it
		challengeBytes, err := base64.StdEncoding.DecodeString(challengeBase64)
		if err != nil {
			return res, err
		}

		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			log.Printf("[ERROR] ParseChallengeMessage failed: %s", err)
			return res, err
		}

		// Extract domain from user credentials, or use target domain from challenge response
		var username, domain string
		userparts := strings.SplitN(t.client.username, "\\", 2)
		if len(userparts) == 1 {
			domain = challenge.TargetInfo.StringValue(ntlm.MsvAvNbDomainName)
			username = t.client.username
		} else {
			domain = userparts[0]
			username = userparts[1]
		}

		ns.SetUserInfo(username, t.client.password, domain)
		// FIXME: Remove this
		// log.Printf("[INFO] Username: %v, password %v, domain: %v", username, t.client.password, domain)

		ns.ProcessChallengeMessage(challenge)

		// Send authenticate message
		authenticate, err := ns.GenerateAuthenticateMessage()
		if err != nil {
			return res, err
		}

		req.Header.Set("Authorization", authSchemeNegotiate+" "+base64.StdEncoding.EncodeToString(authenticate.Bytes()))
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
		req.ContentLength = int64(body.Len())
	}

	// Encrypt the request body if mode enabled
	mode := ns.GetNegotiatedMode()
	if mode.Confidentiality {
		if err := t.encodeEncryptedRequest(req); err != nil {
			return res, err
		}
	}

	// Send request
	res, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return res, err
	}

	if res.StatusCode == 200 {

		// Check if authentication is persistent. If header not present, assume true. See https://msdn.microsoft.com/en-us/library/cc236621.aspx
		persistedAuthToken := res.Header.Get("Persistent-Auth")
		if persistedAuthToken == "" || persistedAuthToken == "true" {
			t.authenticated = true
		}

		// Decrypt the response body if negotiated
		if mode.Confidentiality {
			if err := t.decodeEncryptedResponse(res); err != nil {
				return nil, err
			}
		}

		t.sequenceNumber++

	} else if res.StatusCode == 401 {
		// Authentication lost. Reset request and re-authenticate
		req.Header.Set("Content-Type", contentType)
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
		req.ContentLength = int64(body.Len())

		t.authenticated = false

		goto reauthenticate
		// FIXME: Commence re-authentication
	}

	return res, err
}

// Searches the HTTP response for a WWW-Authenticate header matching the given scheme and returns the first challenge
// RFC2617 allows for multiple challenges to be returned however this method returns only the first
func getAuthenticationChallenge(res *http.Response, scheme string) (challenge string, err error) {
	// Read challenge in the WWW-Authenticate header
	wwwAuthenticate := res.Header["wwwAuthenticate"]
	if wwwAuthenticate == nil {
		return "", errors.New("No WWW-Authenticate header in response")
	}

	// Search authenticate headers for given scheme
	for _, v := range wwwAuthenticate {
		authTokens := strings.Fields(v)
		if authTokens[0] == scheme {
			// Return the first challenge only
			return authTokens[1], nil
		}
	}

	// Nothing found
	return "", errors.New("No Negotiate authorization header found in response")
}

// Rewrite the body of the request as a NegotiateEncryptedMessage according to the Web Services Management Protocol Extensions for Windows Vista
// using the NTLM credentials established in the authentication process
func (t NegotiateEncryptedTransport) encodeEncryptedRequest(req *http.Request) (err error) {

	ns := t.ntlmSession

	if req.Body == nil {
		err := errors.New("Response has no body")
		return err
	}

	// Read unencrypted request body
	body := bytes.Buffer{}
	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			return err
		}

		req.Body.Close()
	}

	// Write encrypted body back using MIME multipart media encapsualtion
	// Part 1
	bodyBuf := bytes.Buffer{}
	// wsmpEncryptedBodyWriter := multipart.NewWriter(&bodyBuf)

	// Work-around for golang issue #18768 (mime/multipart: SetBoundary validation is overly restrictive)
	// Use random boundary and then search/replace later
	//if err := ntlmBodyWriter.SetBoundary(multipartBoundary); err != nil {
	//	return nil, errors.New("Failed to set boundary: " + err.Error())
	//}

	//h1 := textproto.MIMEHeader{}
	//h1.Add(mimeHeaderContentType, textprotoSPNEGOEncrypted)
	//h1.Add(mimeHeaderOriginalContent, fmt.Sprintf("type=%s;Length=%d", req.Header.Get(mimeHeaderContentType), body.Len()))
	//wsmpEncryptedBodyWriter.CreatePart(h1)

	bodyBuf.WriteString("--" + multipartBoundary + CRLF)
	bodyBuf.WriteString("Content-Type: " + mimeMediaTypeSPNEGOEncrypted + CRLF)
	bodyBuf.WriteString(fmt.Sprintf("OriginalContent: type=%s;Length=%d", req.Header.Get("Content-Type"), body.Len()) + CRLF)

	// Part 2
	//h2 := textproto.MIMEHeader{}
	//h2.Add(mimeHeaderContentType, textprotoOctetStream)
	//p2, err := wsmpEncryptedBodyWriter.CreatePart(h2)
	//if err != nil {
	//	return nil, err
	//}

	bodyBuf.WriteString("--" + multipartBoundary + CRLF)
	bodyBuf.WriteString("Content-Type: " + mimeMediaTypeOctetStream + CRLF)

	// Seal and the sign the request body
	log.Printf("[INFO] NTLM sealing message")
	encryptedBody, mac, err := ns.Wrap(body.Bytes(), t.sequenceNumber)
	if err != nil {
		return err
	}

	//	log.Printf("[INFO] NTLM signing message")
	//	mac, err := ns.Mac(body.Bytes(), )
	//	if err != nil {
	//		return err
	//	}

	// Write the encrypted message (length(mac) + mac + encryptedBody)
	lengthField := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthField, uint32(len(mac)))
	//p2.Write(lengthField)
	//p2.Write(mac)
	//p2.Write(encryptedBody)

	//bodyBuf.WriteString(CRLF)
	bodyBuf.Write(lengthField)
	bodyBuf.Write(mac)
	bodyBuf.Write(encryptedBody)

	// Close message
	//	mimeBody.WriteString("--" + multipartBoundary + CRLF)
	//wsmpEncryptedBodyWriter.Close()
	bodyBuf.WriteString("--" + multipartBoundary + "--" + CRLF)

	// Fix for golang issue #18768 (mime/multipart: SetBoundary validation is overly restrictive)
	//wsmpEncryptedBody := bytes.Replace(bodyBuf.Bytes(), []byte(wsmpEncryptedBodyWriter.Boundary()), []byte(multipartBoundary), -1)
	//wsmpEncryptedBody = bytes.Replace(wsmpEncryptedBody, []byte(mimeHeaderOriginalContent), []byte(mimeHeaderOriginalContent), -1)
	encBody := bodyBuf.Bytes()

	// Send request
	log.Printf("[INFO] Sending message")
	req.Header.Set("Content-Type", fmt.Sprintf("%s;protocol=\"%s\";boundary=\"%s\"", mimeMediaTypeMultipartEncrypted, mimeMediaTypeSPNEGOEncrypted, multipartBoundary))
	req.Body = ioutil.NopCloser(bytes.NewReader(encBody))
	req.ContentLength = int64(len(encBody))

	return nil
}

func (t NegotiateEncryptedTransport) decodeEncryptedResponse(res *http.Response) (err error) {

	ns := t.ntlmSession

	if res.Body == nil {
		err := errors.New("Response has no body")
		return err
	}

	log.Printf("[DEBUG] Commencing decode of encrypted response")

	// Confirm that response is a multipart message containing SPNEGO encrypted content
	mediaType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		return err
	}

	if mediaType != mimeMediaTypeMultipartEncrypted || params["protocol"] != mimeMediaTypeSPNEGOEncrypted {
		err := fmt.Errorf("Response body has wrong MIME type [%s] or protocol [%s]", mediaType, params["protocol"])
		return err
	}

	// Read the multipart body
	body := bytes.Buffer{}
	body.Grow(int(res.ContentLength))
	if n, err := body.ReadFrom(io.LimitReader(res.Body, res.ContentLength)); err != nil {
		err := fmt.Errorf("Unexpected error reading body: %s", err)
		return err
	} else if n != res.ContentLength {
		err := fmt.Errorf("Read from body returns less than Content-Length bytes")
		return err
	}
	res.Body.Close()

	// Splice the multipart body into its parts
	parts := bytes.Split(body.Bytes(), []byte("--"+params["boundary"]+CRLF))

	// Validate the headers in the first part
	// Note: parts[0] contains any preample before the first boundary and is ignored
	// Microsoft Web Services Management Protocol Extensions for Windows Vista does not use valid MIME formatting
	// We need to add an extra CRLF to make up for the missing body
	p1Buf := bytes.Buffer{}
	p1Buf.Write(parts[1])
	p1Buf.WriteString(CRLF)

	p1 := textproto.NewReader(bufio.NewReader(bytes.NewReader(p1Buf.Bytes())))
	h1, err := p1.ReadMIMEHeader()
	if err != nil {
		err := fmt.Errorf("Unexpected error reading headers from first part: %s", err)
		return err
	} else if h1.Get("Content-Type") != mimeMediaTypeSPNEGOEncrypted {
		err := fmt.Errorf("First part of multipart response body has wrong content type [%s]", h1.Get("Content-Type"))
		return err
	}

	// Microsoft Web Services Management Protocol Extensions for Windows Vista does not use valid MIME formatting
	// We need to add an extra CRLF to make up for the missing CRLF between headers and body
	p2 := bufio.NewReader(bytes.NewReader(parts[2]))
	line, isPrefix, err := p2.ReadLine()
	if err != nil {
		err := fmt.Errorf("Unexpected error reading second part: %s", err)
		return err
	} else if isPrefix {
		err := fmt.Errorf("Second part of multipart response body has unexpected header [%s]", line)
		return err
	}

	h2Buf := bytes.Buffer{}
	h2Buf.Write(line)
	h2Buf.WriteString(CRLF)
	h2Buf.WriteString(CRLF)

	h2Reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(h2Buf.Bytes())))
	h2, err := h2Reader.ReadMIMEHeader()
	if err != nil {
		err := fmt.Errorf("Unexpected error reading headers from second part: %s", err)
		return err
	} else if h2.Get("Content-Type") != mimeMediaTypeOctetStream {
		err := fmt.Errorf("Second part of multipart response body has wrong content type [%s]", h2.Get("Content-Type"))
		return err
	}

	// Read the original content type to determine length of body
	var originalContentLength uint32
	originalContent := h1.Get("OriginalContent")
	originalContentParams := strings.Split(originalContent, ";")
	for _, param := range originalContentParams {
		if strings.HasPrefix(param, "Length=") {
			length, err := strconv.ParseUint(strings.TrimPrefix(param, "Length="), 10, 32)
			if err != nil {
				err := fmt.Errorf("Unable to read OriginalContent length: %s", err)
				return err
			}
			originalContentLength = uint32(length)
		}
	}

	// Check that content length was found
	if originalContentLength == 0 {
		err := fmt.Errorf("OriginalContent header missing length parameter or is zero")
		return err
	}

	// Now read encrypted message and signature
	lengthField := make([]byte, 4)
	if n, err := io.ReadAtLeast(p2, lengthField, len(lengthField)); err != nil {
		err := fmt.Errorf("Unable to decode encrypted message - unexpected error: %s", err)
		return err
	} else if n != len(lengthField) {
		err := fmt.Errorf("Unable to decode encrypted message - insuffient bytes to read length field")
		return err
	}

	length := binary.LittleEndian.Uint32(lengthField)

	mac := make([]byte, length)
	if n, err := io.ReadAtLeast(p2, mac, len(mac)); err != nil {
		err := fmt.Errorf("Unable to decode encrypted message - unexpected error: %s", err)
		return err
	} else if n != len(mac) {
		err := fmt.Errorf("Unable to decode encrypted message - insuffient bytes to read MAC")
		return err
	}

	encMessage := make([]byte, originalContentLength)
	if n, err := io.ReadAtLeast(p2, encMessage, len(encMessage)); err != nil {
		err := fmt.Errorf("Unable to decode encrypted message - unexpected error: %s", err)
		return err
	} else if n != len(encMessage) {
		err := fmt.Errorf("Unable to decode encrypted message - insufficient bytes to read encrypted message")
		return err
	}

	// Finally, unseal the encrypted message
	message, ok, err := ns.Unwrap(encMessage, mac, t.sequenceNumber)
	if ok != true {
		err := fmt.Errorf("Unable to unencrypt message - incorrect MAC")
		return err
	} else if err != nil {
		err := fmt.Errorf("Unable to unencrypt message - %s", err)
		return err
	}

	// And validate signature
	//	if verified, err := ns.VerifyMac(message, mac, c.sequenceNumber); err != nil {
	//		err := fmt.Errorf("Unable to verify MAC - unexpected error: %s", err)
	//		return err
	//	} else if !verified {
	//		err := fmt.Errorf("MAC of response message does not verify. Discarding response")
	//		return err
	//	}

	// Fix response and return
	res.Header.Set("Content-Type", strings.TrimPrefix(originalContent, "type="))
	res.Body = ioutil.NopCloser(bytes.NewReader(message))
	res.ContentLength = int64(len(message))

	return nil
}