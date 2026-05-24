// DDD role: ValueObject
// Internal package alias — do NOT define #Sensitivity here independently.
// The canonical definition lives in schemas/secret_storage/sensitivity.cue.
// This file re-exports it as a package-level alias so all files in the
// policy_permissions package may reference #Sensitivity without an explicit import.

package policy_permissions

import "fapp.dev/merkle/schemas/secret_storage"

// #Sensitivity is the canonical sensitivity enum defined in the secret_storage
// bounded context. It is referenced here as a package-level alias; any file
// within this package may use #Sensitivity directly.
// Canonical source: schemas/secret_storage/sensitivity.cue
#Sensitivity: secret_storage.#Sensitivity
