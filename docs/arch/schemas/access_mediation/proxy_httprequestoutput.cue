// DDD role: ValueObject

package access_mediation

#HttpRequestOutput: {
	status_code: #StatusCode
	// response_body is returned only when the Namespace Policy permits it.
	response_body?: #ResponseBody
	headers?:       {[string]: string}
}

// #HttpDownloadInput describes the input shape for the "http.download" operation.
