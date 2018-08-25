// Command acmecli is a shell-script interface to the acme-go library.
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/square/go-jose"
	"github.com/tommie/acme-cli"
	"github.com/tommie/acme-go"
)

var (
	dirURI    = flag.String("dir", "", "URI of ACME server directory")
	regURI    = flag.String("reg", "", "URI of account registration")
	keyPath   = flag.String("key", "", "local path to account private key")
	verbosity = flag.Bool("v", false, "increase output verbosity")

	certFormat   = flag.String("certformat", "pem", "certificate output format {der, pem, chain:{der, pem}}")
	contactURIs  = flag.String("contact", "", "add a contact URI for new registrations")
	agreementURI = flag.String("agreement", "", "set an agreement URI for registrations")
)

func main() {
	flag.CommandLine.Usage = func() { showUsage(os.Stdout) }
	flag.Parse()

	if flag.NArg() < 1 {
		showUsage(os.Stderr)
		os.Exit(1)
	}

	ec, err := run(flag.Arg(0), flag.Args()[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(os.Args[0]), err)
	}

	os.Exit(ec)
}

func run(cmd string, args []string) (int, error) {
	switch cmd {
	case "help":
		showHelp(os.Stdout)

	case "newreg":
		if *dirURI == "" {
			return 1, fmt.Errorf("missing -dir option")
		}
		key, err := readPrivateKey()
		if err != nil {
			return 2, err
		}
		if err := newRegistration(*dirURI, key); err != nil {
			return 10, err
		}

	case "reg":
		acc, err := newClientAccount()
		if err != nil {
			return 2, err
		}
		if err := getRegistration(acc); err != nil {
			return 10, err
		}

	case "updatereg":
		acc, err := newClientAccount()
		if err != nil {
			return 2, err
		}
		if err := updateRegistration(acc); err != nil {
			return 10, err
		}

	case "issuecert":
		if len(args) < 2 {
			return 1, fmt.Errorf("expected one CSR file path and a challenge solver command")
		}
		acc, err := newClientAccount()
		if err != nil {
			return 2, err
		}
		cw, err := certWriterByFormat(*certFormat, acc)
		if err != nil {
			return 2, err
		}
		key, err := readPrivateKey()
		if err != nil {
			return 2, err
		}
		s := acmecli.NewProcessSolver(&jose.JsonWebKey{Key: key}, args[1], args[1:], nil)
		if err := issueCertificate(cw, acc, args[0], s); err != nil {
			return 10, err
		}

	case "certs":
		acc, err := newClientAccount()
		if err != nil {
			return 2, err
		}
		if len(args) == 0 {
			if err := listCertificates(acc, *verbosity); err != nil {
				return 10, err
			}
		} else {
			cw, err := certWriterByFormat(*certFormat, acc)
			if err != nil {
				return 2, err
			}
			if err := getCertificates(cw, acc, args); err != nil {
				return 10, err
			}
		}

	case "revokecert":
		if len(args) != 1 {
			return 10, fmt.Errorf("expected one certificate file path")
		}
		acc, err := newClientAccount()
		if err != nil {
			return 2, err
		}
		if err := revokeCertificate(acc, args[0]); err != nil {
			return 10, err
		}

	default:
		showHelp(os.Stderr)
		return 1, fmt.Errorf("unknown command: %s", cmd)
	}

	return 0, nil
}

func showHelp(f io.Writer) {
	showUsage(f)
	fmt.Fprintln(f, "\nOptions:")
	flag.CommandLine.SetOutput(f)
	flag.CommandLine.PrintDefaults()
	fmt.Fprintln(f, `
Commands:
  help
    Show this help text.

  newreg
    Register a new account. Outputs registration URI.
    If a ToS has to be accepted, its URI is also listed.

  reg
    Show information about the account registration.

  updatereg
    Update an account. Can be used to e.g. accept the ToS.

  issuecert <csr-path> <solver-command>...
    Issue a certificate for a given X.509 certificate signing request.

  certs
    List URIs of issued certificates.

  certs <uri>...
    Output certificates for the given URIs.

  revokecert <uri>
    Revoke the given certificate.`)
}

func showUsage(f io.Writer) {
	fmt.Fprintf(f, "usage: %s [<option>...] <command> [<arg>...]\n", filepath.Base(os.Args[0]))
}

func newRegistration(dirURI string, key crypto.PrivateKey) error {
	opts := registrationOpts()
	acc, reg, err := acme.RegisterAccount(dirURI, key, opts...)
	if err != nil {
		return err
	}

	fmt.Println("URI: ", acc.URI)
	return showRegistration(os.Stdout, reg)
}

func getRegistration(acc *acme.ClientAccount) error {
	reg, err := acc.Registration()
	if err != nil {
		return err
	}

	return showRegistration(os.Stdout, reg)
}

func updateRegistration(acc *acme.ClientAccount) error {
	opts := registrationOpts()
	reg, err := acc.UpdateRegistration(opts...)
	if err != nil {
		return err
	}

	return showRegistration(os.Stdout, reg)
}

func showRegistration(f io.Writer, reg *acme.Registration) error {
	bs, err := reg.Key.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	fmt.Fprintln(f, "Key-Thumbprint-SHA256: ", base64.URLEncoding.EncodeToString(bs))

	for _, uri := range reg.ContactURIs {
		fmt.Fprintln(f, "Contact: ", uri)
	}

	fmt.Fprintln(f, "Terms-Of-Service: ", reg.TermsOfServiceURI)
	if reg.AgreementURI != "" {
		fmt.Fprintln(f, "Agreement: ", reg.AgreementURI)
	}

	return nil
}

func issueCertificate(cw certWriter, acc *acme.ClientAccount, path string, solver acme.Solver) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	csr, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	if b, _ := pem.Decode(csr); b != nil && b.Type == "CERTIFICATE REQUEST" {
		csr = b.Bytes
	}

	c, err := acme.NewCertificateIssuer(acc).AuthorizeAndIssue(csr, solver)
	if err != nil {
		return err
	}

	return cw(os.Stdout, c)
}

func getCertificates(cw certWriter, acc *acme.ClientAccount, uris []string) error {
	for _, uri := range uris {
		c, err := acc.Certificate(uri)
		if err != nil {
			return err
		}
		if err := cw(os.Stdout, c); err != nil {
			return err
		}
	}

	return nil
}

func listCertificates(acc *acme.ClientAccount, v bool) error {
	uris, err := acc.CertificateURIs()
	if err != nil {
		return err
	}

	for _, uri := range uris {
		fmt.Println("URI: ", uri)

		if !v {
			continue
		}

		c, err := acc.Certificate(uri)
		if err != nil {
			return err
		}
		if err := showCertificate(os.Stdout, c); err != nil {
			return err
		}
		fmt.Println()
	}

	return nil
}

func showCertificate(f io.Writer, c *acme.Certificate) error {
	xc, err := x509.ParseCertificate(c.Bytes)
	if err != nil {
		return err
	}
	fmt.Fprintln(f, "Subject-Common-Name: ", xc.Subject.CommonName)
	fmt.Fprintln(f, "Not-Before: ", xc.NotBefore)
	fmt.Fprintln(f, "Not-After: ", xc.NotAfter)
	for _, n := range xc.DNSNames {
		fmt.Fprintln(f, "DNS-Name: ", n)
	}
	for _, iu := range c.IssuerURIs {
		fmt.Fprintln(f, "Issuer: ", iu)
	}

	return nil
}

func revokeCertificate(acc *acme.ClientAccount, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	if b, _ := pem.Decode(bs); b != nil && b.Type == "CERTIFICATE" {
		bs = b.Bytes
	}

	return acc.RevokeCertificate(bs)
}
