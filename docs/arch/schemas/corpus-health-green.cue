// DDD role: ValueObject

package schemas

// #CorpusHealthGreen records the offline gate posture for the dual-tree corpus.
#CorpusHealthGreen: {
	// validate_exit_code must be 0 for a healthy control plane.
	validate_exit_code: 0
	// findings_count must be 0 (no active and no waived findings required).
	findings_count: 0
	// dual_tree documents that docs/arch remains the technical contract root.
	dual_tree: true
}
