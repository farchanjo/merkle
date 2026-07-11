// DDD role: ValueObject

package policy_permissions

// #RevealPolicy is the ValueObject controlling Reveal authorization rules for a Namespace.
// allowed=false makes all reveals unconditionally denied regardless of other fields.
// require_oob_above names the minimum sensitivity level at which OOB Confirmation is mandatory.
// slash_only=true restricts the operator confirmation source to slash commands only,
// preventing programmatic confirmation in automated pipelines.
//
// #Sensitivity used here is the canonical alias defined in sensitivity_alias.cue
// (sourced from secret_storage.#Sensitivity). Do NOT redefine #Sensitivity locally.
#RevealPolicy: {
	allowed: #Allowed
	require_oob_above:   #Sensitivity | *"high"
	slash_only:          bool | *true
}
