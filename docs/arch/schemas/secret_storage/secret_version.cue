// DDD role: Entity

package secret_storage

import "time"

// #SecretVersion records a historical revision of a Secret's private material.
// Created on every vault.rotate.  Retention is governed by the Namespace Policy
// (default retain_count = 3); older versions are garbage-collected according to
// that policy.
//
// retired_reason values:
//   "rotated"      — superseded by a newer version via vault.rotate
//   "deleted"      — parent Secret was deleted; all versions retired
//   "expired"      — expires_at elapsed; vault background job retired the version
//   "compromised"  — operator explicitly marked the version as compromised
#SecretVersion: {
	// secret_id is the UUIDv7 of the parent Secret; never changes.
	secret_id: #SecretId

	// version is the 1-based revision counter; matches the Secret.version at
	// the time this snapshot was taken.
	version: int & >=1

	// private_blob is the encrypted material as it existed at this version.
	private_blob: #PrivateBlob

	// created_at is the RFC 3339 timestamp when this version was sealed.
	created_at: time.Time

	// retired_at is set when this version is superseded or invalidated.
	retired_at?: time.Time

	// retired_reason explains why the version was retired.
	retired_reason?: "rotated" | "deleted" | "expired" | "compromised"
}
