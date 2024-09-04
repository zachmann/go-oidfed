package storage

// TrustMarkedEntitiesStorageBackend is an interface to store information
// about trust marked entities
type TrustMarkedEntitiesStorageBackend interface {
	Write(trustMarkID, entityID string) error
	Delete(trustMarkID, entityID string) error
	Load() error
	TrustMarkedEntities(trustMarkID string) ([]string, error)
	// TrustMarks(entityID string) ([]string, error)
	HasTrustMark(trustMarkID, entityID string) (bool, error)
}
