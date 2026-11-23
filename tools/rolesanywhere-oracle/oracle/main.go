// Records the CreateSession requests that the AWS credential helper (aws_signing_helper)
// signs, so aws-rolesanywhere-credentials can be checked against them.
//
// For every case it issues a certificate (through an intermediate when the case has a chain),
// starts a local HTTP server standing in for Roles Anywhere, runs
// `aws_signing_helper credential-process --endpoint http://127.0.0.1:PORT ...`, and records the
// request the helper sent together with the certificate files it was given.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	trustAnchor = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/anchor-id"
	profile     = "arn:aws:rolesanywhere:us-east-1:111122223333:profile/profile-id"
	role        = "arn:aws:iam::111122223333:role/gateway"
	credentials = `{"credentialSet":[{"credentials":{"accessKeyId":"ASIAEXAMPLE",` +
		`"secretAccessKey":"secret","sessionToken":"token","expiration":"2030-01-01T00:00:00Z"}}],` +
		`"subjectArn":"arn:aws:rolesanywhere:us-east-1:111122223333:subject/s"}`
)

type testCase struct {
	Name  string
	Key   string
	Chain bool
}

var cases = []testCase{
	{"rsa-2048", "rsa-2048", false},
	{"rsa-2048-chain", "rsa-2048", true},
	{"p256", "p256", false},
	{"p256-chain", "p256", true},
	{"p384-chain", "p384", true},
	{"p521", "p521", false},
}

// Request is what the stand-in server received.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Fixture is one recorded case.
type Fixture struct {
	Name          string  `json:"name"`
	Certificate   string  `json:"certificate"`
	Intermediates string  `json:"intermediates,omitempty"`
	PrivateKey    string  `json:"private_key"`
	Request       Request `json:"request"`
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: oracle <aws_signing_helper> <output.json>")
	}
	helper, out := os.Args[1], os.Args[2]
	fixtures := make([]Fixture, 0, len(cases))
	for i, c := range cases {
		fixtures = append(fixtures, record(helper, c, int64(1000+i)))
	}
	data, err := json.MarshalIndent(fixtures, "", "  ")
	check(err)
	check(os.WriteFile(out, append(data, '\n'), 0o644))
}

func record(helper string, c testCase, serial int64) Fixture {
	dir, err := os.MkdirTemp("", c.Name)
	check(err)
	defer os.RemoveAll(dir)

	rootKey := newKey("p256")
	root := issue(nil, nil, rootKey, true, 1)
	issuer, issuerKey := root, rootKey
	var intermediates string
	if c.Chain {
		intermediateKey := newKey("p256")
		intermediate := issue(root, rootKey, intermediateKey, true, 2)
		issuer, issuerKey = intermediate, intermediateKey
		intermediates = encode("CERTIFICATE", intermediate.Raw)
	}
	leafKey := newKey(c.Key)
	leaf := issue(issuer, issuerKey, leafKey, false, serial)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	check(err)

	fixture := Fixture{
		Name:          c.Name,
		Certificate:   encode("CERTIFICATE", leaf.Raw),
		Intermediates: intermediates,
		PrivateKey:    encode("PRIVATE KEY", pkcs8),
	}
	certPath := write(dir, "leaf.pem", fixture.Certificate)
	keyPath := write(dir, "key.pem", fixture.PrivateKey)
	args := []string{
		"credential-process",
		"--certificate", certPath,
		"--private-key", keyPath,
		"--trust-anchor-arn", trustAnchor,
		"--profile-arn", profile,
		"--role-arn", role,
	}
	if c.Chain {
		args = append(args, "--intermediates", write(dir, "intermediates.pem", intermediates))
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	received := make(chan Request, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		check(err)
		headers := map[string]string{"host": r.Host}
		for name, values := range r.Header {
			headers[strings.ToLower(name)] = strings.Join(values, ",")
		}
		if r.ContentLength >= 0 {
			headers["content-length"] = fmt.Sprint(r.ContentLength)
		}
		received <- Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Headers: headers, Body: string(body)}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, credentials)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	args = append(args, "--endpoint", "http://"+listener.Addr().String())
	output, err := exec.Command(helper, args...).CombinedOutput()
	if err != nil {
		fail(fmt.Sprintf("%s: aws_signing_helper failed: %v\n%s", c.Name, err, output))
	}
	if !strings.Contains(string(output), "ASIAEXAMPLE") {
		fail(fmt.Sprintf("%s: unexpected helper output: %s", c.Name, output))
	}
	fixture.Request = <-received
	return fixture
}

func newKey(kind string) crypto.Signer {
	var key crypto.Signer
	var err error
	switch kind {
	case "rsa-2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		fail("unknown key type " + kind)
	}
	check(err)
	return key
}

func issue(parent *x509.Certificate, parentKey crypto.Signer, key crypto.Signer, ca bool, serial int64) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).Lsh(big.NewInt(serial), 96),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("oracle %d", serial)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	check(err)
	cert, err := x509.ParseCertificate(der)
	check(err)
	return cert
}

func encode(label string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
}

func write(dir, name, contents string) string {
	path := filepath.Join(dir, name)
	check(os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
