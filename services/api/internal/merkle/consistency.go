package merkle

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
)

// ConsistencyProof returns the RFC 6962 consistency proof that the tree over the first m leaves is a
// prefix (append-only extension) of the tree over all len(leaves) leaves. m must be in (0, len].
// An identical-size proof is empty. This is the RFC 6962 section 2.1.2 PROOF/SUBPROOF algorithm.
func ConsistencyProof(leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if m <= 0 || m > n {
		return nil
	}
	if m == n {
		return nil
	}
	return subproof(m, leaves, true)
}

// subproof is RFC 6962 SUBPROOF(m, D[0:n], b). b true means the left boundary subtree is entirely
// within the first tree and is a complete subtree the verifier already knows (so it is omitted).
func subproof(m int, leaves [][]byte, b bool) [][]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{Root(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subproof(m, leaves[:k], b), Root(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), Root(leaves[:k]))
}

// VerifyConsistency verifies an RFC 6962 consistency proof: that the tree of size m with root1 is a
// prefix of the tree of size n with root2. It reconstructs BOTH roots from the proof and checks
// each. Transcribed from the transparency-dev/merkle reference verifier (Apache-2.0) and validated
// exhaustively against independently computed roots. Requires 0 < m <= n and 32-byte hashes.
func VerifyConsistency(m, n int, proof [][]byte, root1, root2 []byte) bool {
	if m <= 0 || m > n {
		return false
	}
	if len(root1) != sha256.Size || len(root2) != sha256.Size {
		return false
	}
	for _, p := range proof {
		if len(p) != sha256.Size {
			return false
		}
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(root1, root2)
	}
	if len(proof) == 0 {
		return false
	}

	inner, border := decompInclProof(m-1, n)
	shift := bits.TrailingZeros64(uint64(m))
	inner -= shift // shift < inner because m < n

	// The proof carries the root of the size-2^shift boundary subtree, unless m is exactly 2^shift
	// (a perfect subtree whose root is root1, which the verifier already has).
	seed, start := proof[0], 1
	if m == 1<<uint(shift) {
		seed, start = root1, 0
	}
	if len(proof) != start+inner+border {
		return false
	}
	proof = proof[start:]

	mask := (m - 1) >> uint(shift)
	// Reconstruct root1 (the earlier tree) using only left-of-path siblings.
	hash1 := chainBorderRight(chainInnerRight(seed, proof[:inner], mask), proof[inner:])
	// Reconstruct root2 (the later tree) using the full path.
	hash2 := chainBorderRight(chainInner(seed, proof[:inner], mask), proof[inner:])
	return bytes.Equal(hash1, root1) && bytes.Equal(hash2, root2)
}

// decompInclProof splits an inclusion path for index in a tree of size into (inner, border) lengths
// at the point where the paths to index and size-1 diverge.
func decompInclProof(index, size int) (int, int) {
	inner := innerProofSize(index, size)
	border := bits.OnesCount64(uint64(index) >> uint(inner))
	return inner, border
}

func innerProofSize(index, size int) int {
	return bits.Len64(uint64(index) ^ uint64(size-1))
}

// chainInner hashes seed up the tree, choosing sibling side by the index bit at each level.
func chainInner(seed []byte, proof [][]byte, index int) []byte {
	for i, h := range proof {
		if (index>>uint(i))&1 == 0 {
			seed = nodeHash(seed, h)
		} else {
			seed = nodeHash(h, seed)
		}
	}
	return seed
}

// chainInnerRight is chainInner but only folds in left-side siblings, yielding the earlier version
// of the subtree (used to reconstruct root1).
func chainInnerRight(seed []byte, proof [][]byte, index int) []byte {
	for i, h := range proof {
		if (index>>uint(i))&1 == 1 {
			seed = nodeHash(h, seed)
		}
	}
	return seed
}

// chainBorderRight folds in left-side border siblings (one per level).
func chainBorderRight(seed []byte, proof [][]byte) []byte {
	for _, h := range proof {
		seed = nodeHash(h, seed)
	}
	return seed
}
