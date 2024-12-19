package storage

// TrustMarkedEntitiesStorageBackend is an interface to store information
// about trust marked entities
type TrustMarkedEntitiesStorageBackend interface {
	// Delete marks that a certain trust mark is no longer valid for a certain entity
	Delete(trustMarkID, entityID string) error
	// Block marks that a certain trust mark is blocked for a certain entity
	Block(trustMarkID, entityID string) error
	// Approve marks that a certain trust mark is valid for a certain entity
	Approve(trustMarkID, entityID string) error
	// Request marks that a certain trust mark is pending (waiting for approval) for a certain entity
	Request(trustMarkID, entityID string) error
	// TrustMarkedStatus returns the Status for the trustMarkID
	// entityID combination
	TrustMarkedStatus(trustMarkID, entityID string) (Status, error)
	// HasTrustMark checks if a certain entity has a certain trust mark or not
	HasTrustMark(trustMarkID, entityID string) (bool, error)
	// Active returns a list of entity ids that have a certain trust mark; if an
	// empty trustMarkID is passed all entities that have at least one valid
	// trust mark are returned
	Active(trustMarkID string) ([]string, error)
	// Blocked returns a list of entity ids that have been blocked from a
	// certain trust mark
	Blocked(trustMarkID string) ([]string, error)
	// Pending returns a list of entity ids that have pending approval for a
	// certain trust mark
	Pending(trustMarkID string) ([]string, error)
	// Load loads the storage
	Load() error
}
