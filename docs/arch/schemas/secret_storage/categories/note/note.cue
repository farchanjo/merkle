// DDD role: ValueObject

package note_category

// #CategoryName identifies the note secret category.
// Note is reveal-only; FTS does NOT index the body field.
#CategoryName: "note"

// #PublicMeta holds non-sensitive note metadata visible in vault.list and vault.describe.
#PublicMeta: {
	title:        string
	content_type: "text/plain" | "text/markdown"
	// summary is a human-written one-liner safe for the transcript.
	summary:      string
	keywords:     [...string]
}

// #PrivateBlob holds the full note body encrypted inside the private blob.
// body is never indexed by FTS5 or returned in list/describe responses.
#PrivateBlob: {
	body:                 string
	confidential_summary?: string
}

// #FtsIndexedFields lists the public metadata field names submitted to the FTS5 index.
// body is intentionally excluded; note is reveal-only.
#FtsIndexedFields: [...string] & ["name", "title", "summary", "keywords", "tags"]

// #CategorySchema is the top-level closed schema for a note secret.
#CategorySchema: {
	category:     #CategoryName
	public_meta:  #PublicMeta
	private_blob: #PrivateBlob
}
