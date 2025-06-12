package apimodel

// EntityCollectionRequest is a request to the entity collection endpoint
type EntityCollectionRequest struct {
	FromEntityID   string   `json:"from_entity_id" form:"from_entity_id" query:"from_entity_id" url:"from_entity_id"`
	Limit          uint64   `json:"limit" form:"limit" query:"limit" url:"limit"`
	TrustMarkTypes []string `json:"trust_mark_type" form:"trust_mark_type" query:"trust_mark_type" url:"trust_mark_type"`
	TrustAnchor    string   `json:"trust_anchor" form:"trust_anchor" query:"trust_anchor" url:"trust_anchor"`
	EntityTypes    []string `json:"entity_type" form:"entity_type" query:"entity_type" url:"entity_type"`
	NameQuery      string   `json:"name_query" form:"name_query" query:"name_query"`
	Claims         []string `json:"claims" form:"claims" query:"claims" url:"claims"`
}
