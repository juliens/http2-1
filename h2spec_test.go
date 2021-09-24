package http2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/generic"
	"github.com/summerwind/h2spec/http2"
	"github.com/summerwind/h2spec/spec"
	"github.com/valyala/fasthttp"
)

var sections = []string{
	"http2/3.5/1",
	"http2/3.5/2",
	"http2/4.1/1",
	"http2/4.1/2",
	"http2/4.1/3",
	"http2/4.2/1",
	"http2/4.2/2",
	"http2/4.2/3",
	"http2/4.3/1",
	// "http2/4.3/2",
	"http2/4.3/3",
	"http2/5.1.1/1",
	"http2/5.1.1/2",
	"http2/5.1.2/1",
	"http2/5.1/1",
	"http2/5.1/2",
	"http2/5.1/3",
	"http2/5.1/4",
	"http2/5.1/5",
	"http2/5.1/6",
	"http2/5.1/7",
	"http2/5.1/8",
	"http2/5.1/9",
	"http2/5.1/10",
	"http2/5.1/11",
	"http2/5.1/12",
	"http2/5.1/13",
	// "http2/5.3.1/1",
	// "http2/5.3.1/2",
	// "http2/5.4.1/1",
	"http2/5.4.1/2",
	"http2/5.5/1",
	// "http2/5.5/2",
	"http2/6.1/1",
	"http2/6.1/2",
	"http2/6.1/3",
	// "http2/6.2/1",
	"http2/6.2/2",
	"http2/6.2/3",
	"http2/6.2/4",
	"http2/6.3/1",
	"http2/6.3/2",
	"http2/6.4/1",
	"http2/6.4/2",
	"http2/6.4/3",
	"http2/6.5.2/1",
	"http2/6.5.2/2",
	"http2/6.5.2/3",
	"http2/6.5.2/4",
	"http2/6.5.2/5",
	// "http2/6.5.3/1",
	"http2/6.5.3/2",
	"http2/6.5/1",
	"http2/6.5/2",
	"http2/6.5/3",
	"http2/6.7/1",
	"http2/6.7/2",
	"http2/6.7/3",
	"http2/6.7/4",
	"http2/6.8/1",
	// "http2/6.9.1/1",
	// "http2/6.9.1/2",
	// "http2/6.9.1/3",
	// "http2/6.9.2/1",
	// "http2/6.9.2/2",
	"http2/6.9.2/3",
	// "http2/6.9/1",
	"http2/6.9/2",
	"http2/6.9/3",
	"http2/6.10/1",
	"http2/6.10/2",
	"http2/6.10/3",
	// "http2/6.10/4",
	// "http2/6.10/5",
	"http2/6.10/6",
	"http2/7/1",
	"http2/7/2",
	// "http2/8.1.2.1/1",
	// "http2/8.1.2.1/2",
	"http2/8.1.2.1/3",
	// "http2/8.1.2.1/4",
	// "http2/8.1.2.2/1",
	// "http2/8.1.2.2/2",
	// "http2/8.1.2.3/1",
	// "http2/8.1.2.3/2",
	// "http2/8.1.2.3/3",
	// "http2/8.1.2.3/4",
	// "http2/8.1.2.3/5",
	// "http2/8.1.2.3/6",
	// "http2/8.1.2.3/7",
	// "http2/8.1.2.6/1",
	// "http2/8.1.2.6/2",
	// "http2/8.1.2/1",
	"http2/8.1/1",
	"http2/8.2/1",
}

func launchLocalServer(t *testing.T) int {
	certPEM, keyPEM, err := KeyPair("test.default", time.Time{})
	if err != nil {
		log.Fatalf("Unable to generate certificate: %v", err)
	}

	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			ctx.Response.AppendBodyString(fmt.Sprintf("Test	 HTTP2"))
		},
	}
	ConfigureServer(server)

	ln, err := net.Listen("tcp4", ":0")
	go func() {
		log.Println(server.ServeTLSEmbed(ln, certPEM, keyPEM))
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	portInt, err := strconv.Atoi(port)
	require.NoError(t, err)

	return portInt
}

func TestGeneric(t *testing.T) {
	port := launchLocalServer(t)

	tg := generic.Spec()

	conf := &config.Config{
		Host:     "127.0.0.1",
		Port:     port,
		TLS:      true,
		Insecure: true,
		Path:     "/",
		Timeout:  time.Second,
	}

	tg.Test(conf)
	require.Equal(t, 0, tg.FailedCount)
}

func printTest(tg *spec.TestGroup) {
	for _, group := range tg.Groups {
		printTest(group)
	}
	for i := range tg.Tests {
		fmt.Printf("\"%s/%d\",\n", tg.ID(), i+1)
	}
}



func TestHTTP2(t *testing.T) {
	port := launchLocalServer(t)

	testCases := []struct {
		desc string
	}{
		{desc: "http2/3.5/1"},
		{desc: "http2/3.5/2"},
		{desc: "http2/4.1/1"},
		{desc: "http2/4.1/2"},
		{desc: "http2/4.1/3"},
		{desc: "http2/4.2/1"},
		{desc: "http2/4.2/2"},
		{desc: "http2/4.2/3"},
		{desc: "http2/4.3/1"},
		// { desc: "http2/4.3/2"},
		{desc: "http2/4.3/3"},
		{desc: "http2/5.1.1/1"},
		{desc: "http2/5.1.1/2"},
		{desc: "http2/5.1.2/1"},
		{desc: "http2/5.1/1"},
		{desc: "http2/5.1/2"},
		{desc: "http2/5.1/3"},
		{desc: "http2/5.1/4"},
		{desc: "http2/5.1/5"},
		{desc: "http2/5.1/6"},
		{desc: "http2/5.1/7"},
		{desc: "http2/5.1/8"},
		{desc: "http2/5.1/9"},
		{desc: "http2/5.1/10"},
		{desc: "http2/5.1/11"},
		{desc: "http2/5.1/12"},
		{desc: "http2/5.1/13"},
		// { desc: "http2/5.3.1/1"},
		// { desc: "http2/5.3.1/2"},
		// {desc: "http2/5.4.1/1"},
		{desc: "http2/5.4.1/2"},
		{desc: "http2/5.5/1"},
		// {desc: "http2/5.5/2"},
		{desc: "http2/6.1/1"},
		{desc: "http2/6.1/2"},
		{desc: "http2/6.1/3"},
		// {desc: "http2/6.2/1"},
		{desc: "http2/6.2/2"},
		{desc: "http2/6.2/3"},
		{desc: "http2/6.2/4"},
		{desc: "http2/6.3/1"},
		{desc: "http2/6.3/2"},
		{desc: "http2/6.4/1"},
		{desc: "http2/6.4/2"},
		{desc: "http2/6.4/3"},
		{desc: "http2/6.5.2/1"},
		{desc: "http2/6.5.2/2"},
		{desc: "http2/6.5.2/3"},
		{desc: "http2/6.5.2/4"},
		{desc: "http2/6.5.2/5"},
		// {desc: "http2/6.5.3/1"},
		{desc: "http2/6.5.3/2"},
		{desc: "http2/6.5/1"},
		{desc: "http2/6.5/2"},
		{desc: "http2/6.5/3"},
		{desc: "http2/6.7/1"},
		{desc: "http2/6.7/2"},
		{desc: "http2/6.7/3"},
		{desc: "http2/6.7/4"},
		{desc: "http2/6.8/1"},
		// {desc: "http2/6.9.1/1"},
		// {desc: "http2/6.9.1/2"},
		// {desc: "http2/6.9.1/3"},
		// {desc: "http2/6.9.2/1"},
		// {desc: "http2/6.9.2/2"},
		{desc: "http2/6.9.2/3"},
		// {desc: "http2/6.9/1"},
		{desc: "http2/6.9/2"},
		{desc: "http2/6.9/3"},
		{desc: "http2/6.10/1"},
		{desc: "http2/6.10/2"},
		{desc: "http2/6.10/3"},
		// {desc: "http2/6.10/4"},
		// {desc: "http2/6.10/5"},
		{desc: "http2/6.10/6"},
		{desc: "http2/7/1"},
		{desc: "http2/7/2"},
		// {desc: "http2/8.1.2.1/1"},
		// {desc: "http2/8.1.2.1/2"},
		{desc: "http2/8.1.2.1/3"},
		// {desc: "http2/8.1.2.1/4"},
		// {desc: "http2/8.1.2.2/1"},
		// {desc: "http2/8.1.2.2/2"},
		// {desc: "http2/8.1.2.3/1"},
		// {desc: "http2/8.1.2.3/2"},
		// {desc: "http2/8.1.2.3/3"},
		// {desc: "http2/8.1.2.3/4"},
		// {desc: "http2/8.1.2.3/5"},
		// {desc: "http2/8.1.2.3/6"},
		// {desc: "http2/8.1.2.3/7"},
		// {desc: "http2/8.1.2.6/1"},
		// {desc: "http2/8.1.2.6/2"},
		// {desc: "http2/8.1.2/1"},
		{desc: "http2/8.1/1"},
		{desc: "http2/8.2/1"},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			tg := http2.Spec()

			conf := &config.Config{
				Host:     "127.0.0.1",
				Port:     port,
				TLS:      true,
				Insecure: true,
				Path:     "/",
				Timeout:  time.Second,
				Sections: []string{test.desc},
			}

			tg.Test(conf)

			require.Equal(t, 0, tg.FailedCount)
		})
	}
}

// DefaultDomain Traefik domain for the default certificate.
const DefaultDomain = "TEST DEFAULT CERT"

// KeyPair generates cert and key files.
func KeyPair(domain string, expiration time.Time) ([]byte, []byte, error) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey)})

	certPEM, err := PemCert(rsaPrivKey, domain, expiration)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// PemCert generates PEM cert file.
func PemCert(privKey *rsa.PrivateKey, domain string, expiration time.Time) ([]byte, error) {
	derBytes, err := derCert(privKey, expiration, domain)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func derCert(privKey *rsa.PrivateKey, expiration time.Time, domain string) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	if expiration.IsZero() {
		expiration = time.Now().Add(365 * (24 * time.Hour))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: DefaultDomain,
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
}
