// DDD role: ValueObject

package identity_and_sealing

// #UnsealPreconditions captures the runtime flags that the Vault Agent
// must evaluate before transitioning from "sealed" to "unsealing".
// These conditions are checked once, at the start of the unseal sequence,
// before any key material is loaded into protected memory.
//
// Rules enforced by the companion Rego policy (unseal_preconditions.rego):
//   - security_profile == "paranoid" AND mlock_succeeded == false  → fatal deny
//   - entropy_seeded == false (any profile)                        → fatal deny
//   - keychain_reachable == false AND security_profile != "relaxed" → deny
//
// A relaxed profile tolerates keychain unavailability (CI / headless path)
// but still requires entropy and does not make mlock failures fatal.
// A balanced or paranoid profile requires a reachable keychain.
// A paranoid profile additionally makes mlock failure fatal — the process
// MUST NOT proceed without locked memory pages when running in paranoid mode.
#UnsealPreconditions: {
	// security_profile is the active Security Profile for this vault instance.
	// Must match one of the three closed-enum values from #SecurityProfile.
	security_profile: "relaxed" | "balanced" | "paranoid"

	// mlock_succeeded records whether the agent's address space was
	// successfully locked into physical RAM via mlock(2) / VirtualLock.
	// On Linux/macOS, this requires CAP_IPC_LOCK or a raised RLIMIT_MEMLOCK.
	// On Windows, this requires the SE_LOCK_MEMORY_NAME privilege.
	// true  — memory pages are locked; key material cannot be swapped to disk.
	// false — mlock call failed; key material may reside in swap.
	mlock_succeeded: #MlockSucceeded

	// entropy_seeded records whether the platform entropy source was
	// successfully seeded before any cryptographic operation.  This gates
	// nonce generation, salt generation, and key generation.
	// true  — OsRng initialised without error.
	// false — OsRng failed to read from the OS entropy source (getrandom/CryptGenRandom).
	entropy_seeded: #EntropySeeded

	// keychain_reachable records whether the OS keychain backend responded
	// to a probe call before the unseal sequence started.
	// true  — the keychain API is available and the probe key lookup returned
	//         a result (found or not-found; both are healthy responses).
	// false — the keychain API returned an OS error, a daemon timeout, or
	//         the crate could not find a suitable backend (no Secret Service,
	//         no Keychain.framework, no Windows Credential Store).
	keychain_reachable: #KeychainReachable
}
