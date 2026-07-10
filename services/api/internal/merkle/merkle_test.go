package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return out
}

func TestRoot_EmptyTreeIsSha256OfEmpty(t *testing.T) {
	// RFC 6962: MTH({}) = SHA-256().
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(Root(nil)); got != want {
		t.Errorf("empty root = %s, want %s", got, want)
	}
}

func TestRoot_SingleLeafIsLeafHash(t *testing.T) {
	l := []byte("only")
	if !bytes.Equal(Root([][]byte{l}), LeafHash(l)) {
		t.Error("single-leaf root must equal LeafHash(leaf)")
	}
	// LeafHash is SHA-256(0x00 || leaf), domain-separated from a bare hash.
	h := sha256.Sum256(append([]byte{0x00}, l...))
	if !bytes.Equal(LeafHash(l), h[:]) {
		t.Error("LeafHash must be SHA-256(0x00 || leaf)")
	}
}

func TestRoot_TwoLeavesStructure(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	manual := sha256.New()
	manual.Write([]byte{0x01})
	manual.Write(LeafHash(a))
	manual.Write(LeafHash(b))
	if !bytes.Equal(Root([][]byte{a, b}), manual.Sum(nil)) {
		t.Error("two-leaf root must be SHA-256(0x01 || LeafHash(a) || LeafHash(b))")
	}
}

func TestRoot_UnbalancedSplit(t *testing.T) {
	// n=3 splits at k=2: root = node(node(l0,l1), leaf(l2)).
	l := leaves(3)
	left := Root(l[:2])
	right := Root(l[2:])
	want := nodeHash(left, right)
	if !bytes.Equal(Root(l), want) {
		t.Error("n=3 must split at the largest power of two (2), not the middle")
	}
}

func TestInclusion_RoundTripEveryIndex(t *testing.T) {
	for n := 1; n <= 33; n++ {
		l := leaves(n)
		root := Root(l)
		for m := 0; m < n; m++ {
			path := InclusionProof(l, m)
			if !VerifyInclusion(LeafHash(l[m]), m, n, path, root) {
				t.Fatalf("n=%d index=%d: valid proof did not verify", n, m)
			}
		}
	}
}

func TestInclusion_TamperFails(t *testing.T) {
	l := leaves(8)
	root := Root(l)
	path := InclusionProof(l, 3)

	// Wrong leaf.
	if VerifyInclusion(LeafHash([]byte("not-leaf-3")), 3, 8, path, root) {
		t.Error("a wrong leaf must not verify")
	}
	// Wrong index.
	if VerifyInclusion(LeafHash(l[3]), 4, 8, path, root) {
		t.Error("the right leaf at the wrong index must not verify")
	}
	// Tampered path element.
	bad := make([][]byte, len(path))
	copy(bad, path)
	bad[0] = bytes.Repeat([]byte{0xff}, 32)
	if VerifyInclusion(LeafHash(l[3]), 3, 8, bad, root) {
		t.Error("a tampered audit path must not verify")
	}
	// Wrong-length path.
	if VerifyInclusion(LeafHash(l[3]), 3, 8, path[:len(path)-1], root) {
		t.Error("a truncated path must not verify")
	}
	// Wrong tree size.
	if VerifyInclusion(LeafHash(l[3]), 3, 9, path, root) {
		t.Error("the wrong tree size must not verify")
	}
}

func TestVerifyInclusion_RejectsNonHashWidthInputs(t *testing.T) {
	// Regression for the adversarial-review forgery: without a 32-byte width guard, an attacker
	// who controls the leafHash argument can splice sibling bytes into the "leaf" and reconstruct
	// a genuine root from data that is not a leaf of the tree.
	a, b := []byte("a"), []byte("b")
	l := [][]byte{a, b}
	root := Root(l)
	lh0, lh1 := LeafHash(a), LeafHash(b)

	// 48-byte splice: leafHash = LH0 || LH1[:16], path = [LH1[16:]] reconstructs
	// SHA-256(0x01 || LH0 || LH1) = the honest 2-leaf root.
	splicedLeaf := append(append([]byte{}, lh0...), lh1[:16]...)
	if VerifyInclusion(splicedLeaf, 0, 2, [][]byte{lh1[16:]}, root) {
		t.Error("a 48-byte spliced leaf must not verify against the honest root")
	}
	// Empty-leaf splice: leafHash = "", path = [LH0 || LH1].
	if VerifyInclusion(nil, 0, 2, [][]byte{append(append([]byte{}, lh0...), lh1...)}, root) {
		t.Error("an empty leaf hash must not verify against the honest root")
	}
	// Interior-node-as-leaf: the interior hash is 32 bytes so the width guard cannot catch it.
	// With a LYING tree size (2) it reconstructs the root, which is exactly why VerifyInclusion's
	// contract requires treeSize from the SIGNED proof; lock that residual in so it stays loud.
	l4 := leaves(4)
	root4 := Root(l4)
	interior := Root(l4[:2])
	if !VerifyInclusion(interior, 0, 2, [][]byte{Root(l4[2:])}, root4) {
		t.Error("documentation assertion drifted: the interior-node splice under a lying tree size reconstructs the root, and only the signed tree_size defends it")
	}
	// Under the signed (honest) tree size, the same splice fails: the path is too short for n=4.
	if VerifyInclusion(interior, 0, 4, [][]byte{Root(l4[2:])}, root4) {
		t.Error("an interior node presented as a leaf must not verify under the signed tree size")
	}
	// Oversized path element.
	path := InclusionProof(l, 0)
	bad := [][]byte{append(append([]byte{}, path[0]...), 0x00)}
	if VerifyInclusion(lh0, 0, 2, bad, root) {
		t.Error("a 33-byte path element must not verify")
	}
}

func TestVerifyInclusion_RejectsOutOfRangeIndex(t *testing.T) {
	l := leaves(4)
	root := Root(l)
	if VerifyInclusion(LeafHash(l[0]), -1, 4, InclusionProof(l, 0), root) {
		t.Error("negative index must be rejected")
	}
	if VerifyInclusion(LeafHash(l[0]), 4, 4, InclusionProof(l, 0), root) {
		t.Error("index == treeSize must be rejected")
	}
}
