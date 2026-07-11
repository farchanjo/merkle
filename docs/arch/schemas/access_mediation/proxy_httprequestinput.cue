// DDD role: ValueObject

package access_mediation

#HttpRequestInput: {
	url: #Url
	method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
	// headers_public are injected as-is; auth headers come from the Secret.
	headers_public?: {[string]: string}
	body_template?: #BodyTemplate
}

// #HttpRequestOutput describes the output shape for the "http.request" operation.
