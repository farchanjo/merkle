# package merkle.secret_storage.ad_binding
#
# Enforces the Associated Data (AD) binding invariant required by ADR-0004
# Amendment (XChaCha20-Poly1305 AEAD for blobs, AD binding mandatory).
#
# Every encrypt call MUST carry the Handle URI as associated_data, and that
# value MUST equal the canonical Handle of the target row.  Every decrypt call
# MUST supply the same Handle URI; AEAD authentication failure is treated as a
# fatal blob_integrity error with denial_reason "ad_binding_mismatch".
#
# Input shape:
#   {
#     "op":          "put" | "rotate" | "reveal" | "get" | "use",
#     "handle":      string,          -- canonical Handle URI (write path)
#     "row": {
#       "handle":    string           -- stored row handle (read path)
#     },
#     "encrypt_op": {
#       "associated_data": string     -- AD passed to XChaCha20-Poly1305
#     }
#   }
#
# Rules:
#   1. Deny if encrypt_op has no associated_data field (write or read path).
#   2. Deny if AD != input.handle on write ops (put, rotate).
#   3. Deny if AD != input.row.handle on read ops (reveal, get, use).
#
# allow fires only when no deny rule fires and positive conditions hold.

package merkle.secret_storage.ad_binding

import rego.v1

default allow := false

# ---------------------------------------------------------------------------
# Rule 1: Deny if the encrypt_op carries no associated_data field.
# An encryption or decryption call without AD is non-compliant with ADR-0004
# regardless of whether the op is a write or read.  Fail-closed.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op in {"put", "rotate"}
	not input.encrypt_op.associated_data
	msg := sprintf(
		"AD binding missing: encryption operation for op=%v MUST carry associated_data field bound to the Handle URI",
		[input.op],
	)
}

deny contains msg if {
	input.op in {"reveal", "get", "use"}
	not input.encrypt_op.associated_data
	msg := sprintf(
		"AD binding missing: decryption operation for op=%v MUST carry associated_data field bound to the row Handle URI",
		[input.op],
	)
}

# ---------------------------------------------------------------------------
# Rule 2: Deny if AD does not equal the canonical Handle URI on write ops.
# Prevents ciphertext transplantation: a blob encrypted for one Handle cannot
# be stored under a different Handle without AEAD verification failure.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op in {"put", "rotate"}
	input.encrypt_op.associated_data
	input.encrypt_op.associated_data != input.handle
	msg := sprintf(
		"AD binding mismatch: associated_data=%v but handle=%v; ciphertext transplantation attempt denied",
		[input.encrypt_op.associated_data, input.handle],
	)
}

# ---------------------------------------------------------------------------
# Rule 3: Deny if AD does not equal the row's stored Handle on read ops.
# Detects corrupted blobs where the encrypted AD differs from the row handle,
# whether from transplantation, row swap, or storage corruption.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.op in {"reveal", "get", "use"}
	input.encrypt_op.associated_data
	input.encrypt_op.associated_data != input.row.handle
	msg := sprintf(
		"AD binding mismatch on decrypt: associated_data=%v stored_handle=%v; aborting to prevent partial plaintext exposure",
		[input.encrypt_op.associated_data, input.row.handle],
	)
}

# ---------------------------------------------------------------------------
# Helper: AD equals the correct reference for the current op direction.
# Write ops compare against input.handle; read ops compare against row.handle.
# ---------------------------------------------------------------------------
ad_equals_handle if {
	input.op in {"put", "rotate"}
	input.encrypt_op.associated_data == input.handle
}

ad_equals_handle if {
	input.op in {"reveal", "get", "use"}
	input.encrypt_op.associated_data == input.row.handle
}

# ---------------------------------------------------------------------------
# Allow: all deny rules pass and positive AD equality holds.
# ---------------------------------------------------------------------------
allow if {
	input.op in {"put", "rotate", "reveal", "get", "use"}
	input.encrypt_op.associated_data
	count(deny) == 0
	ad_equals_handle
}
