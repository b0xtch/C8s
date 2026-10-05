package simtee_test

import (
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	simulationTag     = "c8s_simtee"
	simulationPackage = "github.com/confidential-dot-ai/c8s/internal/simtee"
)

// moduleRoot is the directory that holds go.mod.
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
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

// buildsWithoutTheTag reports whether a file under this build constraint is
// in some build made without the simulation's tag: whether the constraint
// holds with that tag false and the others as they may be.
func buildsWithoutTheTag(expr constraint.Expr) bool {
	var tags []string
	var collect func(constraint.Expr)
	collect = func(e constraint.Expr) {
		switch e := e.(type) {
		case *constraint.TagExpr:
			if e.Tag != simulationTag && !slices.Contains(tags, e.Tag) {
				tags = append(tags, e.Tag)
			}
		case *constraint.NotExpr:
			collect(e.X)
		case *constraint.AndExpr:
			collect(e.X)
			collect(e.Y)
		case *constraint.OrExpr:
			collect(e.X)
			collect(e.Y)
		}
	}
	collect(expr)
	for set := 0; set < 1<<len(tags); set++ {
		if expr.Eval(func(tag string) bool {
			at := slices.Index(tags, tag)
			return at >= 0 && set&(1<<at) != 0
		}) {
			return true
		}
	}
	return false
}

// constraintOf is a file's //go:build line, or nil for a file with none.
func constraintOf(t *testing.T, path string, source []byte) constraint.Expr {
	t.Helper()
	for _, line := range strings.Split(string(source), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return nil
		}
		if constraint.IsGoBuild(line) {
			expr, err := constraint.Parse(line)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			return expr
		}
	}
	return nil
}

func TestConstraintsAreReadAsTheToolchainReadsThem(t *testing.T) {
	for line, want := range map[string]bool{
		"//go:build c8s_simtee":                      false,
		"//go:build !c8s_simtee":                     true,
		"//go:build linux && c8s_simtee":             false,
		"//go:build linux && !c8s_simtee":            true,
		"//go:build linux":                           true,
		"//go:build !linux":                          true,
		"//go:build c8s_simtee || linux":             true,
		"//go:build (linux || darwin) && c8s_simtee": false,
		"//go:build !(linux && !c8s_simtee)":         true,
		"//go:build !(linux || !c8s_simtee)":         false,
	} {
		expr, err := constraint.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		if got := buildsWithoutTheTag(expr); got != want {
			t.Errorf("%s: in a build without the tag %v, want %v", line, got, want)
		}
	}
}

// What only a simulation build may say: the engine that takes another root,
// the option that names a simulated authority, and the configuration's word
// for it.
var simulationOnly = regexp.MustCompile(`NewSimulatedEngine|FetchSimulatedCollateral|"simulated-tee"|--simulated-tee|simulatedTEE`)

// rootsWritten is a write to the pool of roots an engine holds evidence to.
var rootsWritten = regexp.MustCompile(`\.roots\s*=[^=]|\broots:\s`)

// No file of a build made without the c8s_simtee tag holds any of the
// simulation: none imports this package, none makes an engine under another
// root than the vendor's or writes the roots an engine holds, and none has
// an option or a configuration word that names a simulated authority. A
// release build cannot be told to accept one, because it has nothing to
// tell.
func TestReleaseBuildHoldsNoSimulation(t *testing.T) {
	root := moduleRoot(t)
	var tagged, seen int
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" || name == "node_modules" || name == "build") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		seen++
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			return err
		}
		imports := false
		for _, spec := range file.Imports {
			if value, err := strconv.Unquote(spec.Path.Value); err == nil && value == simulationPackage {
				imports = true
			}
		}
		if expr := constraintOf(t, rel, source); expr != nil && !buildsWithoutTheTag(expr) {
			if imports || simulationOnly.Match(source) {
				tagged++
			}
			return nil
		}
		// The package's own files are in no build that does not import it.
		if strings.HasPrefix(rel, "internal/simtee/") {
			return nil
		}
		if imports {
			t.Errorf("%s is in builds without the %s tag and imports the simulation", rel, simulationTag)
		}
		if found := simulationOnly.Find(source); found != nil {
			t.Errorf("%s is in builds without the %s tag and says %q", rel, simulationTag, found)
		}
		if strings.HasPrefix(rel, "pkg/session/") && rootsWritten.Match(source) {
			t.Errorf("%s is in builds without the %s tag and writes the roots an engine holds evidence to", rel, simulationTag)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The walk found the tree, and the files that do hold the simulation.
	if seen < 300 || tagged < 6 {
		t.Fatalf("the walk read %d files and found the simulation in %d tagged ones: too few to have looked", seen, tagged)
	}
}

// And what the toolchain itself says of the programs: none links this
// package unless it was built with the tag, and the ones a simulation needs
// then do.
func TestReleaseProgramsLinkNoSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("asks the toolchain for every program's dependencies")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool here")
	}
	root := moduleRoot(t)
	// deps are the packages that the named ones link, together.
	deps := func(tags string, packages ...string) []string {
		t.Helper()
		args := []string{"list", "-deps", "-f", "{{.ImportPath}}"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		cmd := exec.Command(goTool, append(args, packages...)...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		listed, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %v: %v\n%s", packages, err, stderr.String())
		}
		return strings.Fields(string(listed))
	}
	// Every program of the module, and the harness that times a start.
	linked := deps("", "./cmd/...", "./test/...")
	if len(linked) < 200 {
		t.Fatalf("the programs link %d packages: too few to have looked", len(linked))
	}
	if slices.Contains(linked, simulationPackage) {
		t.Errorf("a program links the simulation in a build without the %s tag", simulationTag)
	}
	for _, program := range []string{"./cmd/c8s", "./cmd/c8s-session-guest", "./test/session/warmstart"} {
		if !slices.Contains(deps(simulationTag, program), simulationPackage) {
			t.Errorf("%s does not link the simulation in a build with the %s tag", program, simulationTag)
		}
	}
	// The init of a simulated guest keeps its register in a file and needs
	// none of this package: it stays as small as a TD's.
	if slices.Contains(deps(simulationTag, "./cmd/c8s-session-init"), simulationPackage) {
		t.Errorf("the init links the simulation: a simulated guest's init makes a file and no quote")
	}
}
