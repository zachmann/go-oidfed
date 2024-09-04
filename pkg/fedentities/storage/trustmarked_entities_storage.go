package storage

// TrustMarkedEntitiesStorageBackend is an interface to store information
// about trust marked entities
type TrustMarkedEntitiesStorageBackend interface {
	// Write marks that a certain trust mark is valid for a certain entity
	Write(trustMarkID, entityID string) error
	// Delete marks that a certain trust mark is no longer valid for a certain entity
	Delete(trustMarkID, entityID string) error
	// Load loads the storage
	Load() error
	// TrustMarkedEntities returns a list of entity ids that have a certain trust mark; if en empty trustMarkID is
	// passed all entities that have at least on valid trust marked are returned
	TrustMarkedEntities(trustMarkID string) ([]string, error)
	// HasTrustMark indicates if a certain entity has a certain trust mark
	HasTrustMark(trustMarkID, entityID string) (bool, error)
}
