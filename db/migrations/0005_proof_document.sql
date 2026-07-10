-- 0005_proof_document.sql
-- Store the signed erasure proof WITH the record, so the demo gateway can serve it to the
-- browser-side WebCrypto verifier without a round trip to S3. The S3 Object Lock copy remains the
-- immutable external anchor; this is the serving copy.
--
--   proof_body        the EXACT canonical JSON bytes the ECDSA signature covers (never re-derived)
--   proof_signature   base64 DER-encoded ECDSA P-256 signature over proof_body
--   signer_pubkey_pem the signer's public key (also embedded in the proof document itself; served
--                     separately so a verifier can cross-check the two)

ALTER TABLE erasure_record ADD COLUMN IF NOT EXISTS proof_body STRING;
ALTER TABLE erasure_record ADD COLUMN IF NOT EXISTS proof_signature STRING;
ALTER TABLE erasure_record ADD COLUMN IF NOT EXISTS signer_pubkey_pem STRING;
