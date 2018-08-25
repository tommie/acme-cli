package acmecli

import (
	"bytes"
	"crypto/rsa"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go"
	"github.com/tommie/acme-go/protocol"
)

func TestProcSolverCost(t *testing.T) {
	tsts := []struct {
		cmd string

		want float64
		err  error
	}{
		{
			cmd: "awk '!$0 { exit(0); }'; echo 1",

			want: 1,
		},
		{
			cmd: "awk '!$0 { exit(0); }'",

			err: acme.ErrUnsolvable,
		},
		{
			cmd: "awk '!$0 { exit(0); }'; echo 1; exit 20",

			want: 1,
			err:  fmt.Errorf(`solver "/bin/sh" failed`),
		},
		{
			cmd: "awk '!$0 { exit(0); }'; echo hello",

			err: fmt.Errorf("reading cost"),
		},
	}
	for _, tst := range tsts {
		ps := NewProcessSolver(nil, "/bin/sh", []string{"sh", "-c", tst.cmd}, nil)
		got, err := ps.Cost(nil)
		if !matchError(err, tst.err) {
			t.Errorf("Cost(%q) err: got %v, want prefix %v", tst.cmd, err, tst.err)
		}
		if got != tst.want {
			t.Errorf("Cost(%q): got %v, want %v", tst.cmd, got, tst.want)
		}
	}
}

func TestProcSolverSolve(t *testing.T) {
	tsts := []struct {
		name string
		bin  string
		cmd  string
		cs   []protocol.Challenge

		want []protocol.Response
		err  error
	}{
		{
			name: "none",
			bin:  "/bin/bash",
			cmd:  `awk -F$'\t' 'BEGIN { OFS = FS; } !$0 { exit(0); } { print $1, $3; }'`,
			cs:   nil,

			want: nil,
		},
		{
			name: "two",
			bin:  "/bin/bash",
			cmd:  `awk -F$'\t' 'BEGIN { OFS = FS; } !$0 { exit(0); } { print $1, $3; }'`,
			cs: []protocol.Challenge{
				&protocol.DNS01Challenge{Type: protocol.ChallengeDNS01, Token: "token"},
				&protocol.HTTP01Challenge{Type: protocol.ChallengeHTTP01, Token: "token"},
			},

			want: []protocol.Response{
				&protocol.DNS01Response{
					Resource:         protocol.ResourceChallenge,
					Type:             protocol.ChallengeDNS01,
					KeyAuthorization: "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y",
				},
				&protocol.HTTP01Response{
					Resource:         protocol.ResourceChallenge,
					Type:             protocol.ChallengeHTTP01,
					KeyAuthorization: "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y",
				},
			},
		},
		{
			name: "fail-eof",
			bin:  "/bin/bash",
			cmd:  `awk -F$'\t' '!$0 { exit(0); }'`,
			cs: []protocol.Challenge{
				&protocol.DNS01Challenge{Type: protocol.ChallengeDNS01, Token: "token"},
			},

			err: fmt.Errorf("got 0 responses"),
		},
		{
			name: "fail-type",
			bin:  "/bin/bash",
			cmd:  `awk -F$'\t' 'BEGIN { OFS = FS; } !$0 { exit(0); } { print "http-01", $3; }'`,
			cs: []protocol.Challenge{
				&protocol.DNS01Challenge{Type: protocol.ChallengeDNS01, Token: "token"},
			},

			err: fmt.Errorf("mismatching response type"),
		},
		{
			name: "fail-start",
			bin:  "/nosuchfile",

			err: fmt.Errorf(`starting solver "/nosuchfile": fork/exec`),
		},
	}
	for _, tst := range tsts {
		ps := NewProcessSolver(testJWK, tst.bin, []string{"sh", "-c", tst.cmd}, nil)
		got, stop, err := ps.Solve(tst.cs)
		if err == nil {
			if err := stop(); err != nil {
				t.Errorf("[%s] Solve stop failed: %v", tst.name, err)
			}
		}
		if !matchError(err, tst.err) {
			t.Errorf("[%s] Solve() err: got %v, want prefix %v", tst.name, err, tst.err)
		}
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("[%s] Solve(): got %s, want %s", tst.name, got, tst.want)
		}
	}
}

func TestReadResponse(t *testing.T) {
	tsts := []struct {
		in []string

		want protocol.Response
		err  error
	}{
		{
			in: []string{"dns-01", "keyauth"},

			want: &protocol.DNS01Response{
				Resource:         protocol.ResourceChallenge,
				Type:             protocol.ChallengeDNS01,
				KeyAuthorization: "keyauth",
			},
		},
		{
			in: []string{"http-01", "keyauth"},

			want: &protocol.HTTP01Response{
				Resource:         protocol.ResourceChallenge,
				Type:             protocol.ChallengeHTTP01,
				KeyAuthorization: "keyauth",
			},
		},
		{
			in: []string{"proofOfPossession-01", testPossessionAuth},

			want: &protocol.Possession01Response{
				Resource:      protocol.ResourceChallenge,
				Type:          protocol.ChallengePossession01,
				Authorization: *testPossessionJWS,
			},
		},
		{
			in: []string{"tls-alpn-01"},

			want: &protocol.TLSALPN01Response{
				Resource: protocol.ResourceChallenge,
				Type:     protocol.ChallengeTLSALPN01,
			},
		},
		{
			in: []string{"tls-sni-01", "keyauth"},

			want: &protocol.TLSSNI01Response{
				Resource:         protocol.ResourceChallenge,
				Type:             protocol.ChallengeTLSSNI01,
				KeyAuthorization: "keyauth",
			},
		},
		{
			in: []string{"something"},

			err: fmt.Errorf("unknown challenge response type"),
		},
	}
	for _, tst := range tsts {
		var b bytes.Buffer
		cw := csv.NewWriter(&b)
		if err := cw.Write(tst.in); err != nil {
			t.Fatalf("cw.Write failed: %v", err)
		}
		cw.Flush()

		got, err := readResponse(csv.NewReader(&b))
		if !matchError(err, tst.err) {
			t.Errorf("readResponse(%v) err: got %v, want prefix %v", tst.in, err, tst.err)
		}
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("readResponse(%v): got %s, want %s", tst.in, got, tst.want)
		}
	}
}

func TestWriteChallenge(t *testing.T) {
	tsts := []struct {
		in protocol.Challenge

		want []string
		err  error
	}{
		{
			in: &protocol.DNS01Challenge{
				Type:  protocol.ChallengeDNS01,
				Token: "token",
			},

			want: []string{"dns-01", "token", "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y", "xrUFJ2TvB12Or6QYaPuOiB71Z7o_SgchqN1jFTyKB54"},
		},
		{
			in: &protocol.HTTP01Challenge{
				Type:  protocol.ChallengeHTTP01,
				Token: "token",
			},

			want: []string{"http-01", "token", "token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y"},
		},
		{
			in: &protocol.Possession01Challenge{
				Type:  protocol.ChallengePossession01,
				Certs: []protocol.DERData{protocol.DERData("hello"), protocol.DERData("world")},
			},

			want: []string{"proofOfPossession-01", "aGVsbG8=", "d29ybGQ="},
		},
		{
			in: &protocol.TLSALPN01Challenge{
				Type:  protocol.ChallengeTLSALPN01,
				Token: "token",
			},

			want: []string{
				"tls-alpn-01",
				"xrUFJ2TvB12Or6QYaPuOiB71Z7o_SgchqN1jFTyKB54=",
			},
		},
		{
			in: &protocol.TLSSNI01Challenge{
				Type:  protocol.ChallengeTLSSNI01,
				Token: "token",
				N:     2,
			},

			want: []string{
				"tls-sni-01",
				"token",
				"token.luhDRvWTmOMLRwM2gMkTDdC88jVeIXo9Hm1r_Q6W41Y",
				"c6b5052764ef075d8eafa41868fb8e88.1ef567ba3f4a0721a8dd63153c8a079e.acme.invalid",
				"e3e1b3a270c6b5566cb36f9ca4f0939c.af758bfb4ced915161127327053fbbdb.acme.invalid",
			},
		},
		{
			in: &protocol.GenericChallenge{},

			err: fmt.Errorf("unknown challenge type"),
		},
	}
	for _, tst := range tsts {
		var b bytes.Buffer
		cw := csv.NewWriter(&b)

		if err := writeChallenge(cw, tst.in, testJWK); !matchError(err, tst.err) {
			t.Errorf("writeChallenge(%v) err: got %v, want prefix %v", tst.in, err, tst.err)
		}
		cw.Flush()

		cr := csv.NewReader(&b)
		got, err := cr.Read()
		if err != io.EOF && err != nil {
			t.Fatalf("cw.Read failed: %v", err)
		}
		if !reflect.DeepEqual(got, tst.want) {
			t.Errorf("writeChallenge(%v): got %s, want %s", tst.in, got, tst.want)
		}
	}
}

// matchError returns whether err has pat as a prefix.
func matchError(err, pat error) bool {
	if err == nil || pat == nil {
		return err == pat
	}

	return strings.HasPrefix(err.Error(), pat.Error())
}

var (
	// Generated with mustGeneratePossession01
	testPossessionAuth = "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMS1PcktWV1JMMm1qTWs4Q1FTNGFvWDB2WTJSSGpqUFFiRS1Dd3RTblhEbXc5cGUxTkIzeGM5TEJyQl9wV3BqckpLenlKbThQRXo0WUdETlZDOFV6Q3ciLCJlIjoiQVFBQiJ9fQ.eyJ0eXBlIjoicHJvb2ZPZlBvc3Nlc3Npb24tMDEiLCJpZGVudGlmaWVycyI6W10sYWNjb3VudEtleTp7fQ.kD1HJSEuOs6IYo445HQXRtxzKqObqcD7yGkOAcYRTkV4MXdBTBbPluA1EYWzcMPkJnlSB67k2rS8I7imaWUb9w"
	testPossessionJWS  = mustUnmarshalJWS(testPossessionAuth)
)

func mustUnmarshalJWS(s string) *protocol.JSONWebSignature {
	ret, err := jose.ParseSigned(s)
	if err != nil {
		panic(err)
	}

	return (*protocol.JSONWebSignature)(ret)
}

func mustGeneratePossession01() {
	s, err := jose.NewSigner(jose.RS256, testJWK.Key)
	if err != nil {
		panic(err)
	}
	jws, err := s.Sign([]byte(`{"type":"proofOfPossession-01","identifiers":[],accountKey:{}`))
	if err != nil {
		panic(err)
	}
	fmt.Println(jws.CompactSerialize())
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
