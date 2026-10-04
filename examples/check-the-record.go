// Check an Attesso record: verify signed checkpoints and the inclusion and
// consistency proofs with nothing but the Go standard library.
//
// This is the runnable companion to docs.attesso.com/guides/check-the-record.
// The artifacts are the exact JSON bodies of the record endpoints:
//
//	-jwks          /.well-known/record-log-jwks.json
//	-checkpoint    the checkpoints/latest body, or its "checkpoint" object
//	-previous      an earlier checkpoint you saved (either shape)
//	-consistency   the body of GET /v1/record/consistency?from=<previous size>
//	-record-proof  the body of GET /v1/mandates/{mandate_id}/record-proof
//
// Usage:
//
//	go run check-the-record.go -jwks jwks.json -checkpoint checkpoint.json \
//	    [-previous previous.json -consistency consistency.json] \
//	    [-record-proof record-proof.json]
//
// Every check prints one OK or FAIL line. Exit code 0 = everything verified,
// 1 = at least one check failed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"strings"
)

type envelope struct {
	Format    string `json:"format"`
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type checkpointPayload struct {
	Schema    string  `json:"schema"`
	TreeSize  int64   `json:"tree_size"`
	RootHash  string  `json:"root_hash"`
	CreatedAt string  `json:"created_at"`
	PrevHash  *string `json:"prev_hash"`
}

type consistencyResponse struct {
	FromSize     int64    `json:"from_size"`
	ToSize       int64    `json:"to_size"`
	ToCheckpoint envelope `json:"to_checkpoint"`
	Proof        []string `json:"proof"`
}

type recordProofResponse struct {
	Checkpoint    *envelope     `json:"checkpoint"`
	Entries       []recordEntry `json:"entries"`
	PendingEvents int64         `json:"pending_events"`
}

type recordEntry struct {
	Sequence    int64    `json:"sequence"`
	LeafIndex   int64    `json:"leaf_index"`
	EventDigest string   `json:"event_digest"`
	Proof       []string `json:"proof"`
}

var failures int

func fail(check string, err error) {
	fmt.Printf("FAIL %s: %v\n", check, err)
	failures++
}

func ok(format string, args ...any) {
	fmt.Printf("OK "+format+"\n", args...)
}

func main() {
	jwksPath := flag.String("jwks", "", "path to the record-log JWKS (required)")
	checkpointPath := flag.String("checkpoint", "", "path to a signed checkpoint envelope (required)")
	previousPath := flag.String("previous", "", "path to an earlier checkpoint envelope")
	consistencyPath := flag.String("consistency", "", "path to a consistency response")
	recordProofPath := flag.String("record-proof", "", "path to a record-proof response")
	flag.Parse()

	if err := run(*jwksPath, *checkpointPath, *previousPath, *consistencyPath, *recordProofPath); err != nil {
		fmt.Fprintf(os.Stderr, "check-the-record: %v\n", err)
		os.Exit(1)
	}
	if failures > 0 {
		fmt.Printf("FAILED: %d check(s) did not verify\n", failures)
		os.Exit(1)
	}
	fmt.Println("All checks passed.")
}

func run(jwksPath, checkpointPath, previousPath, consistencyPath, recordProofPath string) error {
	if jwksPath == "" || checkpointPath == "" {
		return errors.New("-jwks and -checkpoint are required")
	}
	if (previousPath == "") != (consistencyPath == "") {
		return errors.New("-previous and -consistency must be given together")
	}

	var keys jwks
	if err := readArtifact(jwksPath, &keys); err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}
	checkpoint, err := readCheckpointArtifact(checkpointPath)
	if err != nil {
		return fmt.Errorf("read checkpoint: %w", err)
	}

	payload, err := verifyEnvelope(checkpoint, keys)
	if err != nil {
		fail("checkpoint", err)
	} else {
		ok("checkpoint: kid=%s tree_size=%d created_at=%s root=%s", kidOf(checkpoint), payload.TreeSize, payload.CreatedAt, short(payload.RootHash))
	}

	if previousPath != "" {
		previous, err := readCheckpointArtifact(previousPath)
		if err != nil {
			return fmt.Errorf("read previous checkpoint: %w", err)
		}
		var consistency consistencyResponse
		if err := readArtifact(consistencyPath, &consistency); err != nil {
			return fmt.Errorf("read consistency response: %w", err)
		}
		previousPayload, err := verifyEnvelope(previous, keys)
		if err != nil {
			fail("previous", err)
		} else {
			ok("previous: kid=%s tree_size=%d root=%s", kidOf(previous), previousPayload.TreeSize, short(previousPayload.RootHash))
		}
		if err == nil {
			checkConsistency(previous, previousPayload, checkpoint, payload, consistency)
		}
	}

	if recordProofPath != "" {
		var proof recordProofResponse
		if err := readArtifact(recordProofPath, &proof); err != nil {
			return fmt.Errorf("read record proof: %w", err)
		}
		checkRecordProof(proof, keys)
	}
	return nil
}

func checkConsistency(previous envelope, previousPayload checkpointPayload, checkpoint envelope, payload checkpointPayload, consistency consistencyResponse) {
	if consistency.FromSize != previousPayload.TreeSize || consistency.ToSize != payload.TreeSize {
		fail("consistency", fmt.Errorf("proof is for sizes %d..%d, want %d..%d", consistency.FromSize, consistency.ToSize, previousPayload.TreeSize, payload.TreeSize))
		return
	}
	if consistency.ToCheckpoint.Payload != checkpoint.Payload {
		fail("consistency", errors.New("the proof is for a different checkpoint than -checkpoint"))
		return
	}
	rootFrom, err := parseHash(previousPayload.RootHash)
	if err != nil {
		fail("consistency", err)
		return
	}
	rootTo, err := parseHash(payload.RootHash)
	if err != nil {
		fail("consistency", err)
		return
	}
	proof, err := parseProof(consistency.Proof)
	if err != nil {
		fail("consistency", err)
		return
	}
	if err := verifyConsistency(consistency.FromSize, consistency.ToSize, rootFrom, rootTo, proof); err != nil {
		fail("consistency", err)
		return
	}
	ok("consistency: tree size %d is contained in size %d", consistency.FromSize, consistency.ToSize)
}

func checkRecordProof(proof recordProofResponse, keys jwks) {
	if proof.Checkpoint == nil {
		ok("record: no checkpoint covers this mandate yet (%d pending events)", proof.PendingEvents)
		return
	}
	payload, err := verifyEnvelope(*proof.Checkpoint, keys)
	if err != nil {
		fail("record checkpoint", err)
		return
	}
	ok("record checkpoint: kid=%s tree_size=%d root=%s", kidOf(*proof.Checkpoint), payload.TreeSize, short(payload.RootHash))
	root, err := parseHash(payload.RootHash)
	if err != nil {
		fail("record checkpoint", err)
		return
	}
	for _, entry := range proof.Entries {
		leaf, err := digestLeaf(entry.EventDigest)
		if err != nil {
			fail("inclusion", fmt.Errorf("sequence %d: %w", entry.Sequence, err))
			continue
		}
		path, err := parseProof(entry.Proof)
		if err != nil {
			fail("inclusion", fmt.Errorf("sequence %d: %w", entry.Sequence, err))
			continue
		}
		if err := verifyInclusion(entry.LeafIndex, payload.TreeSize, leaf, root, path); err != nil {
			fail("inclusion", fmt.Errorf("sequence %d: %w", entry.Sequence, err))
			continue
		}
		ok("inclusion: sequence=%d leaf=%d tree_size=%d", entry.Sequence, entry.LeafIndex, payload.TreeSize)
	}
	ok("record: %d entries verified, %d pending events", len(proof.Entries), proof.PendingEvents)
}

// verifyEnvelope checks the checkpoint signature against the published keys
// and returns the decoded payload. Signature first, fields second: the
// signature is over the exact served bytes.
func verifyEnvelope(env envelope, keys jwks) (checkpointPayload, error) {
	if env.Format != "attesso.record.checkpoint.v1" {
		return checkpointPayload{}, fmt.Errorf("format is %q, want attesso.record.checkpoint.v1", env.Format)
	}
	protected, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return checkpointPayload{}, errors.New("protected header is not base64url")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		return checkpointPayload{}, errors.New("protected header is not JSON")
	}
	if header.Alg != "ES256" || header.Kid == "" {
		return checkpointPayload{}, errors.New("protected header must carry alg ES256 and a kid")
	}
	var key *jwk
	for i := range keys.Keys {
		if keys.Keys[i].Kid == header.Kid {
			key = &keys.Keys[i]
			break
		}
	}
	if key == nil {
		return checkpointPayload{}, fmt.Errorf("no published key matches kid %q", header.Kid)
	}
	if key.Kty != "EC" || key.Crv != "P-256" {
		return checkpointPayload{}, errors.New("published key is not a P-256 EC key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || len(signature) != 64 {
		return checkpointPayload{}, errors.New("signature is not a 64-byte base64url ES256 value")
	}
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil || len(x) != 32 {
		return checkpointPayload{}, errors.New("published key has an invalid x coordinate")
	}
	y, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil || len(y) != 32 {
		return checkpointPayload{}, errors.New("published key has an invalid y coordinate")
	}
	digest := sha256.Sum256([]byte(env.Protected + "." + env.Payload))
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !ecdsa.Verify(publicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return checkpointPayload{}, errors.New("signature did not verify against the published keys")
	}
	raw, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return checkpointPayload{}, errors.New("payload is not base64url")
	}
	var payload checkpointPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return checkpointPayload{}, errors.New("payload is not JSON")
	}
	if payload.TreeSize < 1 {
		return checkpointPayload{}, errors.New("tree_size must be positive")
	}
	if _, err := parseHash(payload.RootHash); err != nil {
		return checkpointPayload{}, err
	}
	return payload, nil
}

// digestLeaf turns "sha256:<hex>" into the RFC 6962 leaf hash
// SHA-256(0x00 || digest).
func digestLeaf(encoded string) ([sha256.Size]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(encoded, prefix) {
		return [sha256.Size]byte{}, errors.New("event_digest must be sha256:<64 hex characters>")
	}
	raw, err := hex.DecodeString(encoded[len(prefix):])
	if err != nil || len(raw) != sha256.Size {
		return [sha256.Size]byte{}, errors.New("event_digest must be sha256:<64 hex characters>")
	}
	return hashLeaf(raw), nil
}

func parseHash(encoded string) ([sha256.Size]byte, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != sha256.Size {
		return [sha256.Size]byte{}, errors.New("hash must be 64 hexadecimal characters")
	}
	var hash [sha256.Size]byte
	copy(hash[:], raw)
	return hash, nil
}

func parseProof(encoded []string) ([][sha256.Size]byte, error) {
	proof := make([][sha256.Size]byte, len(encoded))
	for i, element := range encoded {
		hash, err := parseHash(element)
		if err != nil {
			return nil, fmt.Errorf("proof element %d: %w", i, err)
		}
		proof[i] = hash
	}
	return proof, nil
}

func hashLeaf(digest []byte) [sha256.Size]byte {
	preimage := make([]byte, 0, 1+len(digest))
	preimage = append(preimage, 0x00)
	preimage = append(preimage, digest...)
	return sha256.Sum256(preimage)
}

func hashNode(left, right [sha256.Size]byte) [sha256.Size]byte {
	preimage := make([]byte, 0, 1+2*sha256.Size)
	preimage = append(preimage, 0x01)
	preimage = append(preimage, left[:]...)
	preimage = append(preimage, right[:]...)
	return sha256.Sum256(preimage)
}

// verifyInclusion folds the audit path from the leaf up; fn == sn marks the
// incomplete levels at the tree's right border.
func verifyInclusion(index, size int64, leaf, root [sha256.Size]byte, proof [][sha256.Size]byte) error {
	if size < 1 || index < 0 || index >= size {
		return fmt.Errorf("leaf %d is not in a tree of size %d", index, size)
	}
	fn := index
	sn := size - 1
	hash := leaf
	for _, sibling := range proof {
		if sn == 0 {
			return errors.New("proof has more elements than the tree size allows")
		}
		if fn&1 == 1 || fn == sn {
			hash = hashNode(sibling, hash)
			for fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			hash = hashNode(hash, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("proof is too short for the tree size")
	}
	if hash != root {
		return errors.New("proof does not lead to the checkpoint root")
	}
	return nil
}

// verifyConsistency proves the tree of size fromSize is a prefix of the tree
// of size toSize: one chain recomputes each root from the shared inner
// elements, the border elements hang left of both.
func verifyConsistency(fromSize, toSize int64, rootFrom, rootTo [sha256.Size]byte, proof [][sha256.Size]byte) error {
	switch {
	case fromSize < 1 || toSize < fromSize:
		return fmt.Errorf("cannot prove size %d is part of size %d", fromSize, toSize)
	case fromSize == toSize:
		if len(proof) != 0 {
			return errors.New("proof between equal sizes must be empty")
		}
		if rootFrom != rootTo {
			return errors.New("equal sizes with different roots")
		}
		return nil
	case len(proof) == 0:
		return errors.New("proof is empty")
	}
	inner := bits.Len64(uint64((fromSize - 1) ^ (toSize - 1)))
	border := bits.OnesCount64(uint64(fromSize-1) >> uint(inner))
	shift := bits.TrailingZeros64(uint64(fromSize))
	inner -= shift
	if inner < 0 {
		return errors.New("proof is malformed for these sizes")
	}
	seed := proof[0]
	start := 1
	if fromSize == int64(1)<<shift {
		seed = rootFrom
		start = 0
	}
	if len(proof) != start+inner+border {
		return fmt.Errorf("proof has %d elements, want %d", len(proof), start+inner+border)
	}
	rest := proof[start:]
	mask := uint64(fromSize-1) >> shift

	chained := chain(seed, rest[:inner], mask, true)
	chained = chainBorder(chained, rest[inner:])
	if chained != rootFrom {
		return errors.New("proof does not recompute the earlier root")
	}
	chained = chain(seed, rest[:inner], mask, false)
	chained = chainBorder(chained, rest[inner:])
	if chained != rootTo {
		return errors.New("proof does not lead to the later root")
	}
	return nil
}

// chain folds the inner elements; with rightOnly set, only left-side elements
// are folded, which rebuilds the subtree as it stood at the earlier size.
func chain(seed [sha256.Size]byte, proof [][sha256.Size]byte, mask uint64, rightOnly bool) [sha256.Size]byte {
	for level, sibling := range proof {
		leftSide := (mask>>uint(level))&1 == 1
		if rightOnly && !leftSide {
			continue
		}
		if leftSide {
			seed = hashNode(sibling, seed)
		} else {
			seed = hashNode(seed, sibling)
		}
	}
	return seed
}

func chainBorder(seed [sha256.Size]byte, proof [][sha256.Size]byte) [sha256.Size]byte {
	for _, sibling := range proof {
		seed = hashNode(sibling, seed)
	}
	return seed
}

func kidOf(env envelope) string {
	protected, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return "unknown"
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		return "unknown"
	}
	return header.Kid
}

func short(encoded string) string {
	if len(encoded) > 13 {
		return encoded[:13] + "..."
	}
	return encoded
}

func readArtifact(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// readCheckpointArtifact accepts both shapes the record endpoints produce: the
// whole checkpoints/latest body ({"checkpoint": {...}, "anchors": [...], ...})
// and the bare checkpoint object, so files saved straight from curl work as
// the page shows them.
func readCheckpointArtifact(path string) (envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return envelope{}, err
	}
	var response struct {
		Checkpoint *envelope `json:"checkpoint"`
		Anchors    []any     `json:"anchors"`
		Leaves     *int64    `json:"leaves"`
	}
	if err := json.Unmarshal(raw, &response); err == nil && (response.Anchors != nil || response.Leaves != nil) {
		if response.Checkpoint == nil {
			return envelope{}, fmt.Errorf("%s: the record log has no checkpoint yet", path)
		}
		return *response.Checkpoint, nil
	}
	var checkpoint envelope
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return envelope{}, fmt.Errorf("%s: %w", path, err)
	}
	return checkpoint, nil
}
