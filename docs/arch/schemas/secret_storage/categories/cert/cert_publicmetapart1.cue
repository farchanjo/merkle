// DDD role: ValueObject

package cert_category

#PublicMetaPart1: {
	subject_cn: #SubjectCn
	subject_o?: #SubjectO
	issuer_cn: #IssuerCn
	issuer_o?: #IssuerO
	san: #San
	not_before: #NotBefore // RFC 3339 timestamp
	not_after: #NotAfter // RFC 3339 timestamp
}
