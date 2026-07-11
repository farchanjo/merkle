// DDD role: ValueObject
package identity_and_sealing


// #KeystoreBackend selects the backing implementation of the Keychain port.
//
// - "os":   OS-native keychain only (macOS Keychain, Linux Secret Service,
//           Windows Credential Manager). Fails loud on PersistenceFailed.
// - "file": File-backed encrypted keystore only. Requires
//           MERKLE_KEYSTORE_PASSPHRASE or TTY prompt.
// - "auto": Probe OS keychain first; fall back to file on PersistenceFailed.
#KeystoreBackend: "os" | "file" | "auto"

// #KeystoreConfig governs how the agent persists key material.
#KeystoreConfig: {
	// backend selects the keychain implementation.
	// Default: "auto" (OS-first, file fallback on PersistenceFailed).
	backend: #KeystoreBackend

	// file_path overrides the default keystore file location.
	// Resolved only when backend == "file" or when "auto" falls back to file.
	// Default: ~/.local/share/merkle/keystore.age (or $MERKLE_KEYSTORE_PATH).
	file_path?: string

	// auto_threshold controls when the "auto" backend switches to file.
	// "always"          — always prefer OS; never fall back (equivalent to "os").
	// "on-keychain-error" — fall back on any KeychainError::PersistenceFailed.
	// "never"           — always use file; never probe OS (equivalent to "file").
	// Default: "on-keychain-error".
	auto_threshold?: "always" | "on-keychain-error" | "never"

	role: "ValueObject"
}
