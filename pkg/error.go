package pkg

type Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

const (
	InvalidRequest         = "invalid_request"
	InvalidClient          = "invalid_client"
	InvalidIssuer          = "invalid_issuer"
	NotFound               = "not_found"
	ServerError            = "server_error"
	TemporarilyUnavailable = "temporarily_unavailable"
	UnsupportedParameter   = "unsupported_parameter"
)

func ErrorInvalidRequest(description string) Error {
	return Error{
		Error:            InvalidRequest,
		ErrorDescription: description,
	}
}

func ErrorInvalidClient(description string) Error {
	return Error{
		Error:            InvalidClient,
		ErrorDescription: description,
	}
}
func ErrorInvalidIssuer(description string) Error {
	return Error{
		Error:            InvalidIssuer,
		ErrorDescription: description,
	}
}
func ErrorNotFound(description string) Error {
	return Error{
		Error:            NotFound,
		ErrorDescription: description,
	}
}
func ErrorServerError(description string) Error {
	return Error{
		Error:            ServerError,
		ErrorDescription: description,
	}
}
func ErrorUnsupportedParameter(description string) Error {
	return Error{
		Error:            UnsupportedParameter,
		ErrorDescription: description,
	}
}
func ErrorTemporarilyUnavailable(description string) Error {
	return Error{
		Error:            TemporarilyUnavailable,
		ErrorDescription: description,
	}
}
