package main

import (
	"container/list"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/tommie/acme-go"
)

type certChainWriter struct {
	cw  certWriter
	acc *acme.ClientAccount
}

func (ccw certChainWriter) Write(w io.Writer, cert *acme.Certificate) error {
	q := list.New()
	q.PushBack(cert)
	seen := map[string]bool{}

	for q.Len() > 0 {
		el := q.Front()
		q.Remove(el)
		c := el.Value.(*acme.Certificate)
		if seen[c.URI] {
			continue
		}
		seen[c.URI] = true
		if err := ccw.cw(w, c); err != nil {
			return err
		}

		for _, uri := range c.IssuerURIs {
			c, err := ccw.acc.Certificate(uri)
			if err != nil {
				return err
			}
			q.PushBack(c)
		}
	}

	return nil
}

type certWriter func(io.Writer, *acme.Certificate) error

func certWriterByFormat(f string, acc *acme.ClientAccount) (certWriter, error) {
	if strings.HasPrefix(f, "chain:") {
		cw, err := certWriterByFormat(f[6:], acc)
		if err != nil {
			return nil, err
		}
		return certChainWriter{cw, acc}.Write, nil
	}

	switch f {
	case "der":
		return writeDERCertificate, nil
	case "pem":
		return writePEMCertificate, nil
	default:
		return nil, fmt.Errorf("unknown certificate format: %s", f)
	}
}

func writeDERCertificate(w io.Writer, c *acme.Certificate) error {
	_, err := w.Write(c.Bytes)
	return err
}

func writePEMCertificate(w io.Writer, c *acme.Certificate) error {
	b := &pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{"Location": c.URI},
		Bytes:   c.Bytes,
	}
	return pem.Encode(os.Stdout, b)
}

func registrationOpts() []acme.RegistrationOpt {
	var opts []acme.RegistrationOpt
	if *contactURIs != "" {
		opts = append(opts, acme.WithContactURIs(*contactURIs))
	}
	if *agreementURI != "" {
		opts = append(opts, acme.WithAgreementURI(*agreementURI))
	}
	return opts
}

func readPrivateKey() (crypto.PrivateKey, error) {
	if *keyPath == "" {
		return nil, fmt.Errorf("missing -key option")
	}

	f, err := os.Open(*keyPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("while reading private key %q: %v", *keyPath, err)
	}
	b, _ := pem.Decode(bs)
	if err != nil {
		return nil, fmt.Errorf("while PEM-parsing private key %q: %v", *keyPath, err)
	}

	var key crypto.PrivateKey
	switch b.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	default:
		err = fmt.Errorf("unknown PEM type %q", b.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("while parsing private key %q: %v", *keyPath, err)
	}

	return key, nil
}

func newClientAccount() (*acme.ClientAccount, error) {
	if *dirURI == "" {
		return nil, fmt.Errorf("missing -dir option")
	}
	if *regURI == "" {
		return nil, fmt.Errorf("missing -reg option")
	}

	key, err := readPrivateKey()
	if err != nil {
		return nil, err
	}

	return acme.NewClientAccount(*dirURI, *regURI, key)
}
