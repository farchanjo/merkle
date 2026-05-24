// DDD role: ValueObject

package identity_and_sealing

// #SealedState is the closed enum that describes the lifecycle phase of the
// Vault Agent with respect to the Vault Root Key.
//
// Transitions:
//   sealed        -> unsealing      (unseal command received)
//   unsealing     -> unsealed       (Vault Root Key loaded into protected memory)
//   unsealing     -> sealed         (unseal failed; key material zeroed)
//   unsealed      -> shutting_down  (agent is preparing to stop)
//   shutting_down -> sealed         (key material zeroed; agent exiting)
#SealedState: "sealed" | "unsealing" | "unsealed" | "shutting_down"
