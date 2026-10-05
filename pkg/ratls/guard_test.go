package ratls

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The init-data anchor holds only while every HOST_DATA read comes from a
// verifier's claims: one call site parsing a raw report blob ahead of
// verification is the #63 defect again. Pin it: no non-test file in this
// module may call the raw report/quote parsers or their field getters.
// (Test files are exempt — fixtures parse reports legitimately.)
func TestNoRawReportFieldReads(t *testing.T) {
	if hits := rawReportFieldReads(t, moduleRoot(t)); len(hits) > 0 {
		t.Fatalf("report fields must be read from a verifier's claims, never parsed off a raw report:\n  %s",
			strings.Join(hits, "\n  "))
	}
}

// The guard must be able to fire: a poisoned tree is caught, at the right
// line, for every banned accessor — SNP and TDX alike.
func TestRawReportFieldReadsFires(t *testing.T) {
	for _, tc := range []struct{ needle, call string }{
		{"ReportToProto", "_, _ = abi.ReportToProto(report)"},
		{"QuoteToProto", "_, _ = abi.QuoteToProto(quote)"},
		{"GetHostData", "_ = report.GetHostData()"},
		{"GetMrConfigId", "_ = body.GetMrConfigId()"},
	} {
		t.Run(tc.needle, func(t *testing.T) {
			dir := t.TempDir()
			src := "package x\n\nfunc f(report, quote, body any) {\n\t" + tc.call + "\n}\n"
			if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			hits := rawReportFieldReads(t, dir)
			if len(hits) != 1 || !strings.Contains(hits[0], "x.go:4") || !strings.Contains(hits[0], tc.needle) {
				t.Fatalf("hits = %v, want the poisoned %s call at x.go:4", hits, tc.needle)
			}
		})
	}
}

// A file that may parse a verified quote may do that and nothing else the
// guard bans: an init-data read there is caught like anywhere, and so is a
// quote parsed in any other file.
func TestVerifiedQuoteParsersMayOnlyParse(t *testing.T) {
	for file, why := range verifiedQuoteParsers {
		if why == "" {
			t.Errorf("%s may parse a quote for no stated reason", file)
		}
		dir := t.TempDir()
		write := func(rel, src string) {
			path := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write(file, "package x\n\nfunc f(quote []byte, body any) {\n\t_, _ = abi.QuoteToProto(quote)\n\t_ = body.GetMrConfigId()\n\t_, _ = abi.ReportToProto(quote)\n}\n")
		write(filepath.ToSlash(filepath.Join(filepath.Dir(file), "other.go")), "package x\n\nfunc g(quote []byte) {\n\t_, _ = abi.QuoteToProto(quote)\n}\n")
		hits := rawReportFieldReads(t, dir)
		if len(hits) != 3 {
			t.Fatalf("hits = %v, want the init-data read and the report parse in %s and the quote parse beside it", hits, file)
		}
		for _, hit := range hits {
			if strings.HasPrefix(hit, file+":4 ") {
				t.Errorf("the quote parse in %s is a hit: %s", file, hit)
			}
		}
	}
}

// Test files are exempt — fixtures parse reports legitimately and a production
// build omits them — so a banned call in a _test.go is not a hit.
func TestRawReportFieldReadsExemptsTestFiles(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nfunc f(report any) {\n\t_ = report.GetHostData()\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if hits := rawReportFieldReads(t, dir); len(hits) != 0 {
		t.Fatalf("test files must be exempt, got hits: %v", hits)
	}
}

// verifiedQuoteParsers are the files that may parse a TDX quote, each with
// why. The claims a verifier returns carry nothing of the quoting enclave's
// report or of the PCK certificate, so a verifier that holds those to the
// vendor's identity and TCB documents has to read them off the quote. It
// does so only after the quote's signature has verified, and it reads no
// init data: the field getters stay banned in these files too.
var verifiedQuoteParsers = map[string]string{
	"pkg/session/tdxorigin.go": "holds an already verified quote's quoting enclave, TDX module and TCB levels to Intel's documents",
}

// rawReportFieldReads scans every non-test Go file under root for calls to
// the raw report/quote parsers and field getters.
func rawReportFieldReads(t *testing.T, root string) []string {
	t.Helper()
	banned := map[string]string{
		"ReportToProto": "parses a raw SNP report blob",
		"QuoteToProto":  "parses a raw TDX quote blob",
		"GetHostData":   "reads SNP HOST_DATA off a parsed report",
		"GetMrConfigId": "reads TDX MRCONFIGID off a parsed quote",
	}

	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			// A nested module (its own go.mod, e.g. test/mock-*) is a separate
			// build, not part of this module's guarded tree.
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if what, bad := banned[sel.Sel.Name]; bad {
				r, rerr := filepath.Rel(root, path)
				if rerr != nil {
					r = path
				}
				if _, verified := verifiedQuoteParsers[filepath.ToSlash(r)]; verified && sel.Sel.Name == "QuoteToProto" {
					return true
				}
				hits = append(hits, r+":"+strconv.Itoa(fset.Position(sel.Pos()).Line)+" "+sel.Sel.Name+" ("+what+")")
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return hits
}

// moduleRoot walks up from the package dir to the go.mod root, so the guard
// covers the whole module wherever the test binary runs from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("no go.mod found above the package dir")
		}
		dir = up
	}
}
