// DDD role: ValueObject

package access_mediation

#WriteTempfileInput: {
	// fifo controls whether the tempfile is a named pipe (FIFO) or a regular file.
	fifo: bool | *false
}

// #WriteTempfileOutput describes the output shape for the "write_tempfile" operation.
