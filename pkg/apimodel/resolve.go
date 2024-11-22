package apimodel

// ResolveRequest is a request to the resolve endpoint
type ResolveRequest struct {
	Subject     string   `json:"sub" form:"sub" query:"sub" url:"sub"`
	Anchor      []string `json:"anchor" form:"anchor" query:"anchor" url:"anchor"`
	EntityTypes []string `json:"type" form:"type" query:"type" url:"type"`
}
