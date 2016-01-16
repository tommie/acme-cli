package acmecli

import (
	"crypto"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/square/go-jose"
	"github.com/tommie/acme-go"
	"github.com/tommie/acme-go/protocol"
)

// A SolverMode is an identifier passed in the ACME_MODE environment
// variable. It corresponds with acme.Solver methods.
type SolverMode string

const (
	ModeCanSolve SolverMode = "cansolve"
	ModeSolve    SolverMode = "solve"
)

// A ProcessSolver is an acme.Solver that uses a child process to
// solve challenges. Note an individual solver may
// be instantiated multiple times. It is up to calling code and the
// solver child to block or handle concurrency.
//
// The parent communicates to the child via environment variables,
// stdin and stdout. ACME_MODE is one of the SolverMode
// constants. ACME_ACCOUNT_JWK is a base64-encoded jose.JsonWebKey.
//
// For stdin and stdout, CSV with new-line (record) and tab (field)
// separators are used. stdin receives challenges where the first
// field is the challenge type. stdout provides responses, also with
// the first field being the challenge type.
//
// A non-zero exit code will cause the solver to return failure.
type ProcessSolver struct {
	accKey *jose.JsonWebKey
	name   string
	argv   []string
	attr   os.ProcAttr
}

// NewProcessSolver creates a new process solver. name, argv and attr
// follow the os.StartProcess semantics.
func NewProcessSolver(accKey *jose.JsonWebKey, name string, argv []string, attr *os.ProcAttr) *ProcessSolver {
	if attr == nil {
		attr = &os.ProcAttr{}
	}
	return &ProcessSolver{accKey, name, argv, *attr}
}

// Cost computes the cost of solving the challenges.
//
// It runs the solver in ModeCanSolve, feeds the challenges as CSV
// records and expects a single float64 on stdout. If stdout is empty,
// it is assumed the challenges cannot be solved together.
func (s *ProcessSolver) Cost(cs []protocol.Challenge) (cost float64, errRet error) {
	p, r, stop, err := s.start(cs, ModeCanSolve)
	if err != nil {
		return 0, fmt.Errorf("starting solver %q: %v", s.name, err)
	}
	defer func() {
		if err := stop(); err != nil && errRet == nil {
			errRet = err
		}
	}()

	cr := csv.NewReader(r)
	cr.Comma = '\t'
	cost, err = readCost(cr)
	if err == io.EOF {
		return 0, acme.ErrUnsolvable
	} else if err != nil {
		p.Kill()
		return 0, fmt.Errorf("reading cost from %q: %v", s.name, err)
	}

	return cost, nil
}

// readCost attempts to read a single field of a single CSV record and
// parsing it as a float64. Returns io.EOF if no record is found.
func readCost(cr *csv.Reader) (float64, error) {
	rec, err := cr.Read()
	if err == io.EOF {
		// Empty reply: cannot solve the challenges.
		return 0, io.EOF
	} else if err != nil {
		return 0, err
	}

	if len(rec) != 1 {
		return 0, fmt.Errorf("expected one field, got %v", rec)
	}
	cost, err := strconv.ParseFloat(rec[0], 64)
	if err != nil {
		return 0, fmt.Errorf("expected number, got %q", rec[0])
	}

	return cost, nil
}

// Solve instantiates the solver for the given challenges.
//
// It passes the challenges to the child, emits the blank trailing
// record and waits for responses. The child must output one response
// per challenge, in order.
//
// To stop the instance, call the returned stop function. This will
// close stdin, signaling the child to exit.
func (s *ProcessSolver) Solve(cs []protocol.Challenge) ([]protocol.Response, func() error, error) {
	p, r, stop, err := s.start(cs, ModeSolve)
	if err != nil {
		return nil, nil, fmt.Errorf("starting solver %q: %v", s.name, err)
	}

	cr := csv.NewReader(r)
	cr.Comma = '\t'
	resps, err := readResponses(cr, cs)
	if err != nil {
		p.Kill()
		stop()
		return nil, nil, err
	}

	return resps, stop, nil
}

// readResponses reads len(cs) records from r and parses them into
// protocol.Response objects.
func readResponses(cr *csv.Reader, cs []protocol.Challenge) ([]protocol.Response, error) {
	var ret []protocol.Response
	for i, c := range cs {
		resp, err := readResponse(cr)
		if err == io.EOF {
			return nil, fmt.Errorf("got %d responses, want %d", i, len(cs))
		} else if err != nil {
			return nil, err
		}
		if resp.GetType() != c.GetType() {
			return nil, fmt.Errorf("mismatching response type: got %q, want %q", resp.GetType(), c.GetType())
		}
		ret = append(ret, resp)
	}
	return ret, nil
}

// readResponse reads a single record and parses it.
func readResponse(r *csv.Reader) (protocol.Response, error) {
	rec, err := r.Read()
	if err != nil {
		return nil, err
	}

	t := protocol.ChallengeType(rec[0])
	switch t {
	case protocol.ChallengeDNS01:
		if len(rec) != 2 {
			return nil, fmt.Errorf("expected two fields for %s response, got %v", t, rec)
		}
		return &protocol.DNS01Response{Resource: protocol.ResourceChallenge, Type: t, KeyAuthorization: rec[1]}, nil

	case protocol.ChallengeHTTP01:
		if len(rec) != 2 {
			return nil, fmt.Errorf("expected two fields for %s response, got %v", t, rec)
		}
		return &protocol.HTTP01Response{Resource: protocol.ResourceChallenge, Type: t, KeyAuthorization: rec[1]}, nil

	case protocol.ChallengePossession01:
		if len(rec) != 2 {
			return nil, fmt.Errorf("expected two fields for %s response, got %v", t, rec)
		}
		jws, err := jose.ParseSigned(rec[1])
		if err != nil {
			return nil, err
		}
		return &protocol.Possession01Response{Resource: protocol.ResourceChallenge, Type: t, Authorization: protocol.JSONWebSignature(*jws)}, nil

	case protocol.ChallengeTLSSNI01:
		if len(rec) != 2 {
			return nil, fmt.Errorf("expected two fields for %s response, got %v", t, rec)
		}
		return &protocol.TLSSNI01Response{Resource: protocol.ResourceChallenge, Type: t, KeyAuthorization: rec[1]}, nil

	default:
		return nil, fmt.Errorf("unknown challenge response type: %v", rec)
	}
}

// start starts a new child process and feeds it the provided
// challenges. Returns the process, the stdout reader, and a function
// to stop the process.
func (s *ProcessSolver) start(cs []protocol.Challenge, mode SolverMode) (*os.Process, io.ReadCloser, func() error, error) {
	attr := *&s.attr
	jwk, err := json.Marshal(s.accKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if attr.Env == nil {
		attr.Env = os.Environ()
	}
	attr.Env = append(attr.Env, "ACME_MODE="+string(mode), "ACME_ACCOUNT_JWK="+string(jwk))

	stdin, stdinw, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	defer stdin.Close()
	go func() {
		cw := csv.NewWriter(stdinw)
		cw.Comma = '\t'
		for _, c := range cs {
			if err := writeChallenge(cw, c, s.accKey); err != nil {
				panic(fmt.Errorf("error: writing challenge %+v: %v\n", c, err))
			}
		}
		// Terminate challenges with an empty record.
		cw.Write(nil)
		cw.Flush()
	}()

	stdoutr, stdout, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	defer stdout.Close()
	if len(attr.Files) <= syscall.Stderr {
		attr.Files = make([]*os.File, syscall.Stderr+1)
	}
	attr.Files[syscall.Stdin] = stdin
	attr.Files[syscall.Stdout] = stdout
	attr.Files[syscall.Stderr] = os.Stderr

	p, err := os.StartProcess(s.name, s.argv, &attr)
	stop := func() error {
		go func() {
			defer stdoutr.Close()
			bs := make([]byte, 1024)
			for {
				// Continue reading the stdout pipe and then close,
				// to avoid SIGPIPE in the child.
				_, err := stdoutr.Read(bs)
				if err == io.EOF {
					break
				} else if err != nil {
					return
				}
			}
		}()

		// Closing stdin signals to the child to stop the solver and terminate.
		err := stdinw.Close()
		if err != nil {
			return err
		}
		ps, err := p.Wait()
		if err != nil {
			return err
		}
		if !ps.Success() {
			return fmt.Errorf("solver %q failed: %s", s.name, ps)
		}
		return nil
	}
	return p, stdoutr, stop, err
}

// writeChallenge marshals the challenge and writes it as CSV.
func writeChallenge(w *csv.Writer, c protocol.Challenge, accKey *jose.JsonWebKey) error {
	switch cc := c.(type) {
	case *protocol.DNS01Challenge:
		ka, err := protocol.KeyAuthz(cc.Token, accKey)
		if err != nil {
			return err
		}
		return w.Write([]string{string(cc.GetType()), cc.Token, ka})

	case *protocol.HTTP01Challenge:
		ka, err := protocol.KeyAuthz(cc.Token, accKey)
		if err != nil {
			return err
		}
		return w.Write([]string{string(cc.GetType()), cc.Token, ka})

	case *protocol.Possession01Challenge:
		rec := []string{string(cc.GetType())}
		for _, bs := range cc.Certs {
			rec = append(rec, base64.URLEncoding.EncodeToString(bs))
		}
		return w.Write(rec)

	case *protocol.TLSSNI01Challenge:
		ka, err := protocol.KeyAuthz(cc.Token, accKey)
		if err != nil {
			return err
		}
		rec := []string{string(cc.GetType()), cc.Token, ka}
		z := ka
		h := crypto.SHA256.New()
		for i := 0; i < cc.N; i++ {
			h.Reset()
			h.Write([]byte(z))
			// EncodeToString casing is undefined. https://github.com/golang/go/issues/11254
			z = strings.ToLower(hex.EncodeToString(h.Sum(nil)))
			rec = append(rec, strings.Join([]string{z[:32], z[32:], protocol.TLSSNI01Suffix}, "."))
		}
		return w.Write(rec)

	default:
		return fmt.Errorf("unknown challenge type: %#v", c)
	}
}
