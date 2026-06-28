-- 004: head-commitment MAC column for the audit pinned head (MERK-003).
--
-- The chain verifier authenticates the pinned head with
--   hmac_head = HMAC(key, head_hash || head_seq || head_id || entry_count)
-- and fails closed (ChainOutcome::HeadMacMismatch) on a NULL/absent tag during a
-- keyed verification pass. The column is nullable: heads written before this
-- migration (and recovery/legacy heads) lack the tag, and the next keyed
-- AuditWriter::append re-stamps it on the following audit event.
--
-- Authored as a forward migration (rather than editing 001_initial.sql in place)
-- so existing vault databases keep their applied-migration checksums and are not
-- reset. Fresh installs converge here via 001 -> 004.
--
-- NOTE: the MERK-002 fix (reject a missing HMAC tag when a key is present) is
-- enforced in the chain verifier (ChainOutcome::MissingHmac), independent of the
-- DB schema, so the `audit_entries.hmac` column intentionally stays nullable and
-- is NOT rebuilt to NOT NULL here -- a table rebuild on a live vault is not worth
-- the marginal defense-in-depth when the verifier already fails closed.

ALTER TABLE pinned_head ADD COLUMN hmac_head TEXT;
