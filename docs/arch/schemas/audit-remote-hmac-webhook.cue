// DDD role: ValueObject
package schemas

// #AuditRemoteWebhookEnabled product gate.
// DDD role: ValueObject
#AuditRemoteWebhookEnabled: true

// #AuditRemoteHmacWebhook fire-and-forget delivery.
// DDD role: ValueObject
#AuditRemoteHmacWebhook: {
	enabled:           #AuditRemoteWebhookEnabled
	env_var:           "MERKLE_AUDIT_WEBHOOK_URL"
	header:            "X-Merkle-Audit-HMAC"
	delivery:          "fire_and_forget"
	blocks_commit:     false
	content_type:      "application/json"
}
