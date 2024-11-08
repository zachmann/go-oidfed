package apimodel

// ResolveRequest is a request to the resolve endpoint
type ResolveRequest struct {
	Subject     string   `json:"sub" form:"sub" query:"sub"`
	Anchor      []string `json:"anchor" form:"anchor" query:"anchor"`
	EntityTypes []string `json:"type" form:"type" query:"type"`
}
