// DDD role: ValueObject

package access_mediation

#HttpUploadInput: {
	url: #Url
	local_path: #LocalPath
	method:     "POST" | "PUT" | *"POST"
}

// #HttpUploadOutput describes the output shape for the "http.upload" operation.
