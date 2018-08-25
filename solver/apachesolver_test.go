package solver

import (
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
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
			},

			want: 1,
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
			t.Errorf("[%s] Cost(): got %v, want %v", tst.name, got, tst.want)
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
