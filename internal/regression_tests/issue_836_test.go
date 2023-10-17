package regressiontests

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type CmpCircuit struct {
	Left      frontend.Variable
	Right     frontend.Variable
	ExpCmpRes frontend.Variable
}

func (c *CmpCircuit) Define(api frontend.API) error {
	r := api.Cmp(c.Left, c.Right)
	api.AssertIsEqual(r, c.ExpCmpRes)
	return nil
}

type AssertIsLessOrEqCircuit struct {
	Smaller, Bigger frontend.Variable
}

func (c *AssertIsLessOrEqCircuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.Smaller, c.Bigger)
	return nil
}

type MathCmpAssertIsLessOrEqCircuitBounded struct {
	Left  frontend.Variable
	Right frontend.Variable
}

func (c *MathCmpAssertIsLessOrEqCircuitBounded) Define(api frontend.API) error {
	cmper := cmp.NewBoundedComparator(api, big.NewInt(6), false)
	cmper.AssertIsLessEq(c.Left, c.Right)
	return nil
}

type MathCmpAssertIsLessOrEqCircuitFull struct {
	Left  frontend.Variable
	Right frontend.Variable
}

func (c *MathCmpAssertIsLessOrEqCircuitFull) Define(api frontend.API) error {
	api.AssertIsEqual(1, cmp.IsLessOrEqual(api, c.Left, c.Right))
	return nil
}

func getNBitsHint() (solver.HintID, error) {
	for _, v := range solver.GetRegisteredHints() {
		if solver.GetHintName(v) == "github.com/consensys/gnark/std/math/bits.nBits" {
			return solver.GetHintID(v), nil
		}
	}
	return 0, fmt.Errorf("nBits hint not found")
}

func TestIssue836Cmp(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentNoHintGood := CmpCircuit{
		Left:      10,
		Right:     5,
		ExpCmpRes: 1,
	}
	assignmentNoHintBad := CmpCircuit{
		Left:      5,
		Right:     10,
		ExpCmpRes: 1,
	}
	assignmentHintBad := CmpCircuit{
		Left:      10,
		Right:     5,
		ExpCmpRes: -1,
	}
	assignmentHintBad2 := CmpCircuit{
		Left:      10,
		Right:     0,
		ExpCmpRes: -1,
	}
	toReplaceHint, err := getNBitsHint()
	if err != nil {
		t.Fatalf("couldn't find hint to replace: %v", err)
	}
	assert.CheckCircuit(&CmpCircuit{}, test.WithValidAssignment(&assignmentNoHintGood), test.WithInvalidAssignment(&assignmentNoHintBad))
	assert.CheckCircuit(&CmpCircuit{}, test.WithInvalidAssignment(&assignmentHintBad), test.WithInvalidAssignment(&assignmentHintBad2), test.NoTestEngine(), test.WithSolverOpts(solver.OverrideHint(toReplaceHint, maliciousNbitsHint)))
}

func TestIssue836AssertIsLess(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentNoHintGood := AssertIsLessOrEqCircuit{
		Smaller: 5,
		Bigger:  10,
	}
	assignmentNoHintBad := AssertIsLessOrEqCircuit{
		Smaller: 11,
		Bigger:  10,
	}
	assignmentHintBad := AssertIsLessOrEqCircuit{
		Smaller: 10,
		Bigger:  5,
	}
	assignmentHintBad2 := AssertIsLessOrEqCircuit{
		Smaller: 10,
		Bigger:  0,
	}
	toReplaceHint, err := getNBitsHint()
	if err != nil {
		t.Fatalf("couldn't find hint to replace: %v", err)
	}
	assert.CheckCircuit(&AssertIsLessOrEqCircuit{}, test.WithValidAssignment(&assignmentNoHintGood), test.WithInvalidAssignment(&assignmentNoHintBad))
	assert.CheckCircuit(&AssertIsLessOrEqCircuit{}, test.WithInvalidAssignment(&assignmentHintBad), test.WithInvalidAssignment(&assignmentHintBad2), test.NoTestEngine(), test.WithSolverOpts(solver.OverrideHint(toReplaceHint, maliciousNbitsHint)))
}

func TestIssue836MathCmpAssertIsLessEqBounded(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentNoHintGood := MathCmpAssertIsLessOrEqCircuitBounded{
		Left:  5,
		Right: 10,
	}
	assignmentNoHintBad := MathCmpAssertIsLessOrEqCircuitBounded{
		Left:  11,
		Right: 10,
	}
	assignmentHintBad := MathCmpAssertIsLessOrEqCircuitBounded{
		Left:  10,
		Right: 5,
	}
	assignmentHintBad2 := MathCmpAssertIsLessOrEqCircuitBounded{
		Left:  10,
		Right: 0,
	}

	toReplaceHint, err := getNBitsHint()
	if err != nil {
		t.Fatalf("couldn't find hint to replace: %v", err)
	}
	assert.CheckCircuit(&MathCmpAssertIsLessOrEqCircuitBounded{}, test.WithValidAssignment(&assignmentNoHintGood), test.WithInvalidAssignment(&assignmentNoHintBad))
	assert.CheckCircuit(&MathCmpAssertIsLessOrEqCircuitBounded{}, test.WithInvalidAssignment(&assignmentHintBad), test.WithInvalidAssignment(&assignmentHintBad2), test.NoTestEngine(), test.WithSolverOpts(solver.OverrideHint(toReplaceHint, maliciousNbitsHint)))
}

func TestIssueXXXMathCmpAssertIsLessEqFull(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentNoHintGood := MathCmpAssertIsLessOrEqCircuitFull{
		Left:  5,
		Right: 10,
	}
	assignmentNoHintBad := MathCmpAssertIsLessOrEqCircuitFull{
		Left:  11,
		Right: 10,
	}
	assignmentHintBad := MathCmpAssertIsLessOrEqCircuitFull{
		Left:  10,
		Right: 5,
	}
	assignmentHintBad2 := MathCmpAssertIsLessOrEqCircuitBounded{
		Left:  10,
		Right: 0,
	}
	toReplaceHint, err := getNBitsHint()
	if err != nil {
		t.Fatalf("couldn't find hint to replace: %v", err)
	}
	assert.CheckCircuit(&MathCmpAssertIsLessOrEqCircuitFull{}, test.WithValidAssignment(&assignmentNoHintGood), test.WithInvalidAssignment(&assignmentNoHintBad))
	assert.CheckCircuit(&MathCmpAssertIsLessOrEqCircuitFull{}, test.WithInvalidAssignment(&assignmentHintBad), test.WithInvalidAssignment(&assignmentHintBad2), test.NoTestEngine(), test.WithSolverOpts(solver.OverrideHint(toReplaceHint, maliciousNbitsHint)))
}

func maliciousNbitsHint(mod *big.Int, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	// This is a malicious hint. If n is less equal than 5, then add the
	// modulus. This creates a non-unique binary decomposition of the value.
	if n.Cmp(big.NewInt(5)) <= 0 {
		n = n.Add(n, mod)
	}
	for i := 0; i < len(results); i++ {
		results[i].SetUint64(uint64(n.Bit(i)))
	}
	return nil
}

type MyRangeCheckCircuit struct {
	X            frontend.Variable `gnark:",public"`
	Y            frontend.Variable `gnark:",public"`
	Z            frontend.Variable `gnark:",public"`
	DoRangeCheck bool
}

func (circuit *MyRangeCheckCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Z, api.Add(circuit.X, circuit.Y))
	if circuit.DoRangeCheck {
		rangeChecker := rangecheck.New(api)
		rangeChecker.Check(circuit.X, 8)
	}
	return nil
}

// To run this test, use:
// go test -v -run TestRangeCheckSolidityVerifier -tags=solccheck
// Also make sure you've installed gnark-solidity-checker
// and run `export PATH=$PATH:$HOME/go/bin` to add it to your PATH

func TestRangeCheckSolidityVerifier(t *testing.T) {
	assert := test.NewAssert(t)
	assignmentValid := MyRangeCheckCircuit{
		X:            5,
		Y:            10,
		Z:            15,
		DoRangeCheck: true,
	}

	// This should fail, because groth16 Solidity verifier doesn't support range checks
	// but this succeeds
	assert.CheckCircuit(
		&MyRangeCheckCircuit{},
		test.WithValidAssignment(&assignmentValid),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)

	t.Errorf("This test should panic")
}
