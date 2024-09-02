package pkg

// Error is type for holding an error
type Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Constants for some error
const (
	InvalidRequest         = "invalid_request"
	InvalidClient          = "invalid_client"
	InvalidIssuer          = "invalid_issuer"
	NotFound               = "not_found"
	ServerError            = "server_error"
	TemporarilyUnavailable = "temporarily_unavailable"
	UnsupportedParameter   = "unsupported_parameter"
)

// ErrorInvalidRequest returns an Error for using InvalidRequest
func ErrorInvalidRequest(description string) Error {
	return Error{
		Error:            InvalidRequest,
		ErrorDescription: description,
	}
}

// ErrorInvalidClient returns an Error for using InvalidClient
func ErrorInvalidClient(description string) Error {
	return Error{
		Error:            InvalidClient,
		ErrorDescription: description,
	}
}

// ErrorInvalidIssuer returns an Error for using InvalidIssuer
func ErrorInvalidIssuer(description string) Error {
	return Error{
		Error:            InvalidIssuer,
		ErrorDescription: description,
	}
}

// ErrorNotFound returns an Error for using NotFound
func ErrorNotFound(description string) Error {
	return Error{
		Error:            NotFound,
		ErrorDescription: description,
	}
}

// ErrorServerError returns an Error for using ServerError
func ErrorServerError(description string) Error {
	return Error{
		Error:            ServerError,
		ErrorDescription: description,
	}
}

// ErrorUnsupportedParameter returns an Error for using UnsupportedParameter
func ErrorUnsupportedParameter(description string) Error {
	return Error{
		Error:            UnsupportedParameter,
		ErrorDescription: description,
	}
}

// ErrorTemporarilyUnavailable returns an Error for using TemporarilyUnavailable
func ErrorTemporarilyUnavailable(description string) Error {
	return Error{
		Error:            TemporarilyUnavailable,
		ErrorDescription: description,
	}
}
