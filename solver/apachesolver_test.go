package solver

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/square/go-jose"
	"github.com/tommie/acme-cli"
	"github.com/tommie/acme-go"
	"github.com/tommie/acme-go/protocol"
)

func TestApacheSolverCost(t *testing.T) {
	tsts := []struct {
		name string
		cs   []protocol.Challenge

		want float64
		err  error
	}{
		{
			name: "none",
			cs:   nil,

			err: acme.ErrUnsolvable,
		},
		{
			name: "two",
			cs: []protocol.Challenge{
				&protocol.HTTP01Challenge{Type: protocol.ChallengeHTTP01, Token: "token"},
				&protocol.TLSSNI01Challenge{Type: protocol.ChallengeTLSSNI01, Token: "token"},
			},

			want: 1 + 2,
		},
		{
			name: "fail-type",
			cs: []protocol.Challenge{
				&protocol.DNS01Challenge{Type: protocol.ChallengeDNS01, Token: "token"},
			},

			err: acme.ErrUnsolvable,
		},
	}
	for _, tst := range tsts {
		ps := newApacheSolver("", "")
		got, err := ps.Cost(tst.cs)
		if !matchError(err, tst.err) {
			t.Errorf("[%s] Cost() err: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if got != tst.want {
			t.Errorf("[%s] Cost(): got %s, want %s", tst.name, got, tst.want)
		}
	}
}

func TestApacheSolverHTTP01(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "apachesolver_test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	chalDir := filepath.Join(tmpDir, "challenges")
	configFile := filepath.Join(tmpDir, "apache.conf")
	if err := os.Mkdir(chalDir, 0700); err != nil {
		t.Fatalf("Mkdir(.../challenges) failed: %v", err)
	}

	ps := newApacheSolver(chalDir, configFile)
	got, stop, err := ps.Solve([]protocol.Challenge{&protocol.HTTP01Challenge{Type: protocol.ChallengeHTTP01, Token: "token"}})
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("Solve stop failed: %v", err)
		}
	}()

	want := &protocol.HTTP01Response{
		Resource:         protocol.ResourceChallenge,
		Type:             protocol.ChallengeHTTP01,
		KeyAuthorization: "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y",
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("Solve responses: got %v, want %v", got[0], want)
	}
	if bs, err := ioutil.ReadFile(filepath.Join(chalDir, "token")); err != nil {
		t.Errorf("ReadFile(token) failed: %v", err)
	} else if want := []byte(want.KeyAuthorization + "\n"); !reflect.DeepEqual(bs, want) {
		t.Errorf("ReadFile(token): got %s, want %s", bs, want)
	}
}

func TestApacheSolverTLSSNI01(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "apachesolver_test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	configFile := filepath.Join(tmpDir, "apache.conf")

	ps := newApacheSolver("", configFile)
	n := 2
	got, stop, err := ps.Solve([]protocol.Challenge{&protocol.TLSSNI01Challenge{Type: protocol.ChallengeTLSSNI01, Token: "token", N: n}})
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("Solve stop failed: %v", err)
		}
	}()

	want := &protocol.TLSSNI01Response{
		Resource:         protocol.ResourceChallenge,
		Type:             protocol.ChallengeTLSSNI01,
		KeyAuthorization: "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y",
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("Solve responses: got %v, want %v", got[0], want)
	}
	bs, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Errorf("ReadFile(apache.conf) failed: %v", err)
	}
	cfs, kfs := apacheCertsAndKeys(string(bs))
	if want := n; len(cfs) != want {
		t.Errorf("apacheCertsAndKeys(%s): got %d cert files, want %d", bs, len(cfs), want)
	}
	if len(cfs) != len(kfs) {
		t.Fatalf("apacheCertsAndKeys(%s): got %d cert files, but %d key files", bs, len(cfs), len(kfs))
	}
	ns := protocol.TLSSNI01Names(want.KeyAuthorization, n)
	for i, cf := range cfs {
		cert, err := tls.LoadX509KeyPair(cf, kfs[i])
		if err != nil {
			t.Errorf("LoadX509KeyPair(%q, %q) failed: %v", cf, kfs[i], err)
		}
		c, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Errorf("ParseCertificate(%q) failed: %v", cf, err)
		}
		// Assumes apachesolver creates certs in order.
		if err := c.VerifyHostname(ns[i]); err != nil {
			t.Errorf("VerifyHostname(%q) failed: %v", cf, err)
		}
	}
}

// apacheCertsAndKeys parses an Apache configuration fragment and
// finds SSL certificate and key file paths.
func apacheCertsAndKeys(conf string) (certs []string, keys []string) {
	re := regexp.MustCompile(`(?m)^\s*(SSLCertificateFile|SSLCertificateKeyFile)\s+(.*)$`)
	for _, ss := range re.FindAllStringSubmatch(conf, -1) {
		switch ss[1] {
		case "SSLCertificateFile":
			certs = append(certs, ss[2])
		case "SSLCertificateKeyFile":
			keys = append(keys, ss[2])
		}
	}
	return
}

func newApacheSolver(chalDir, configFile string) *acmecli.ProcessSolver {
	attr := &os.ProcAttr{
		Env: os.Environ(),
	}
	attr.Env = append(attr.Env,
		"ACME_CHALLENGE_DIR="+chalDir,
		"ACME_CONFIG_FILE="+configFile,
		"ACME_APACHE2CTL=:")

	return acmecli.NewProcessSolver(testJWK, "./apachesolver", nil, attr)
}

// matchError returns whether err has pat as a prefix.
func matchError(err, pat error) bool {
	if err == nil || pat == nil {
		return err == pat
	}

	return strings.HasPrefix(err.Error(), pat.Error())
}

var (
	// testJWK is a JsonWebKey used for tests. Generated by protocol.mustGenerateTestJWK.
	testJWK = mustUnmarshalJWK(`{
	"kty": "RSA",
	"n": "1-OrKVWRL2mjMk8CQS4aoX0vY2RHjjPQbE-CwtSnXDmw9pe1NB3xc9LBrB_pWpjrJKzyJm8PEz4YGDNVC8UzCw",
	"e": "AQAB",
	"d": "vYhi_CbjD3zuiXxTvmV7e8srj1a6e12B3ZTwd5u6Unu13MqiceywGjXP98z18uCrAYgxyHHGQY6X7Ahfm2riAQ",
	"p": "23IPuW88sFRlPOlJ_OUWjQKE7DOXCFyUbeWxD8unk18",
	"q": "-9n1DN65zlVdGXzwxbt1tIxt2Jj8aQMrr-qa_i-Ni9U"
}`)
	// testPublicKey is the raw crypto.PublicKey part of testJWK.
	testPublicKey = testJWK.Key.(*rsa.PrivateKey).Public()
)

// mustUnmarshalJWK takes a JSON string and unmarshals the key. Panics on error.
func mustUnmarshalJWK(s string) *jose.JsonWebKey {
	ret := &jose.JsonWebKey{}
	if err := json.Unmarshal([]byte(s), ret); err != nil {
		panic(err)
	}
	return ret
}
