// Package merkle builds an RFC 6962 Merkle tree over the decision log, additively: the existing
// per-row hash chain is unchanged, and this layer provides efficient inclusion proofs (prove entry
// N is in a tree of a given root without revealing the whole log). Leaf and node hashing follow
// RFC 6962 exactly (domain-separated with 0x00 for leaves, 0x01 for interior nodes), so an
// independent implementation produces identical roots.
package merkle

import (
	"bytes"
	"crypto/sha256"
)

// LeafHash is RFC 6962 MTH of a single leaf: SHA-256(0x00 || leaf).
func LeafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	return h.Sum(nil)
}

// nodeHash is RFC 6962 interior-node hashing: SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n (n >= 2), the
// RFC 6962 split point.
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}

// Root is the RFC 6962 Merkle Tree Hash over the ordered leaves. The empty tree hashes to
// SHA-256 of the empty string.
func Root(leaves [][]byte) []byte {
	n := len(leaves)
	switch {
	case n == 0:
		s := sha256.Sum256(nil)
		return s[:]
	case n == 1:
		return LeafHash(leaves[0])
	default:
		k := largestPowerOfTwoLessThan(n)
		return nodeHash(Root(leaves[:k]), Root(leaves[k:]))
	}
}

// InclusionProof returns the RFC 6962 audit path for the leaf at index m in the tree over leaves.
// The path is ordered leaf-to-root: sibling closest to the leaf first. It panics-free contract: m
// must be in [0, len(leaves)); callers validate before calling.
func InclusionProof(leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(InclusionProof(leaves[:k], m), Root(leaves[k:]))
	}
	return append(InclusionProof(leaves[k:], m-k), Root(leaves[:k]))
}

// VerifyInclusion recomputes the root from a leaf's hash, its index, the tree size, and the audit
// path, and compares it to the expected root. It is the exact inverse of InclusionProof (same split
// and ordering), which keeps it correct for unbalanced trees where naive index-bit walking is
// wrong, and it rejects a path of the wrong length.
//
// Soundness contract for callers: leafHash must be recomputed by the verifier itself via LeafHash
// (never taken from the party asserting inclusion), and treeSize must come from the signed proof,
// not from the endpoint that supplied the audit path. The 0x00/0x01 domain separation only protects
// against interior-node-as-leaf splices when the verifier applies the leaf prefix itself. The root
// signed into an erasure proof is a snapshot at anchor time: after later log appends the live tree
// diverges, so verify inclusion against the signed (root, tree_size) pair, not the current head.
// An RFC 6962 consistency proof (VerifyConsistency in this package) then shows the current tree is
// an append-only extension of that signed snapshot.
func VerifyInclusion(leafHash []byte, m, treeSize int, proof [][]byte, root []byte) bool {
	if m < 0 || m >= treeSize {
		return false
	}
	computed, ok := computeRoot(leafHash, m, treeSize, proof)
	return ok && bytes.Equal(computed, root)
}

func computeRoot(leafHash []byte, m, n int, proof [][]byte) ([]byte, bool) {
	// Every hash in the tree is exactly SHA-256-sized. Without this width guard an attacker who
	// controls leafHash can splice sibling bytes into the "leaf" (e.g. a 48-byte leafHash plus a
	// 16-byte path element reconstructs a real 2-leaf root) and forge inclusion of non-leaf data.
	if len(leafHash) != sha256.Size {
		return nil, false
	}
	for _, p := range proof {
		if len(p) != sha256.Size {
			return nil, false
		}
	}
	if n == 1 {
		if len(proof) != 0 {
			return nil, false
		}
		return leafHash, true
	}
	if len(proof) == 0 {
		return nil, false
	}
	sibling := proof[len(proof)-1] // the top sibling was appended last
	rest := proof[:len(proof)-1]
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		left, ok := computeRoot(leafHash, m, k, rest)
		if !ok {
			return nil, false
		}
		return nodeHash(left, sibling), true
	}
	right, ok := computeRoot(leafHash, m-k, n-k, rest)
	if !ok {
		return nil, false
	}
	return nodeHash(sibling, right), true
}
