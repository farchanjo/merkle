// DDD role: ValueObject

package secret_storage

// _builtinCategories enumerates the built-in category slugs.  These names are
// reserved and MUST NOT be used as #CustomCategory values.
_builtinCategories: "ssh" | "password" | "token" | "env" | "cert" |
	"key" | "database" | "note" | "otp" | "cloud" | "gpg"

// #CustomCategory is a user-defined category slug.  It must conform to the
// general slug pattern and must not shadow any built-in name.
//
// Custom categories require a declared CUE schema under
// docs/arch/schemas/secret_storage/categories/<slug>.cue describing their
// public and private field layout.
//
// The exclusion of built-in names is expressed as a constraint; CUE's
// structural typing does not allow a simple subtraction of a disjunction, so
// implementors SHOULD additionally validate custom slugs against the built-in
// list at application startup.
#CustomCategory: =~ "^[a-z][a-z0-9-]*$"

// #Category is the closed sum of all built-in categories plus any valid
// #CustomCategory.  The built-in arm is listed exhaustively so that CUE
// tooling can flag unknown literals at vet time when a concrete value is
// provided.
#Category: _builtinCategories | #CustomCategory
