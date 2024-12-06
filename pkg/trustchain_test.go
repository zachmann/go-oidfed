package pkg

import (
	"reflect"
	"testing"
	"time"

	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

func TestTrustChains_ExpiresAt(t *testing.T) {
	tests := []struct {
		name            string
		chain           TrustChain
		expiresExpected unixtime.Unixtime
	}{
		{
			name:            "emtpy",
			chain:           TrustChain{},
			expiresExpected: unixtime.Unixtime{},
		},
		{
			name: "single",
			chain: TrustChain{
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{
							Time: time.Unix(
								5, 0,
							),
						},
					},
				},
			},
			expiresExpected: unixtime.Unixtime{Time: time.Unix(5, 0)},
		},
		{
			name: "first min",
			chain: TrustChain{
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{
							Time: time.Unix(
								5, 0,
							),
						},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(10, 0)},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(100, 0)},
					},
				},
			},
			expiresExpected: unixtime.Unixtime{Time: time.Unix(5, 0)},
		},
		{
			name: "other min",
			chain: TrustChain{
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(10, 0)},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{
							Time: time.Unix(
								5, 0,
							),
						},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(100, 0)},
					},
				},
			},
			expiresExpected: unixtime.Unixtime{Time: time.Unix(5, 0)},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				expires := test.chain.ExpiresAt()
				if !expires.Equal(test.expiresExpected.Time) {
					t.Errorf("ExpiresAT() gives %v, but %v expected ", expires, test.expiresExpected)
				}
			},
		)
	}
}

func TestTrustChain_Metadata(t *testing.T) {
	chainRPIA2TA1Metadata := rp1.EntityStatementPayload().Metadata
	chainRPIA2TA1Metadata.RelyingParty.Contacts = append(chainRPIA2TA1Metadata.RelyingParty.Contacts, "ia@example.org")
	chainRPIA2TA2Metadata := chainRPIA2TA1Metadata
	chainRPIA2TA2Metadata.RelyingParty.Contacts = append(
		chainRPIA2TA2Metadata.RelyingParty.Contacts, "ta@foundation.example.org",
	)

	tests := []struct {
		name             string
		chain            TrustChain
		expectedMetadata *Metadata
		errExpected      bool
	}{
		{
			name:             "empty",
			chain:            TrustChain{},
			expectedMetadata: nil,
			errExpected:      true,
		},
		{
			name: "single",
			chain: TrustChain{
				&EntityStatement{EntityStatementPayload: rp1.EntityStatementPayload()},
			},
			expectedMetadata: rp1.EntityStatementPayload().Metadata,
			errExpected:      false,
		},
		{
			name:             "chain rp->ia1->ta1: nil policy",
			chain:            chainRPIA1TA1,
			expectedMetadata: rp1.EntityStatementPayload().Metadata,
			errExpected:      false,
		},
		{
			name:             "chain rp->ia2->ta1",
			chain:            chainRPIA2TA1,
			expectedMetadata: chainRPIA2TA1Metadata,
			errExpected:      false,
		},
		{
			name:             "chain rp->ia2->ta2",
			chain:            chainRPIA2TA2,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				metadata, err := test.chain.Metadata()
				if err != nil {
					if test.errExpected {
						return
					}
					t.Error(err)
					return
				}
				if test.errExpected {
					t.Errorf("expected error, but no error returned")
					return
				}
				if !reflect.DeepEqual(metadata, test.expectedMetadata) {
					t.Errorf(
						"returned Metadata is not what we expected:\n\nReturned:\n%+v\n\nExpected:\n%+v\n\n",
						metadata, test.expectedMetadata,
					)
					return
				}
			},
		)
	}
}

func TestTrustChain_MetaDataPolicyCrit(t *testing.T) {
	chainRPIA2TA1Metadata := rp1.EntityStatementPayload().Metadata
	chainRPIA2TA1Metadata.RelyingParty.Contacts = append(chainRPIA2TA1Metadata.RelyingParty.Contacts, "ia@example.org")
	chainRPIA2TA2Metadata := chainRPIA2TA1Metadata
	chainRPIA2TA2Metadata.RelyingParty.Contacts = append(
		chainRPIA2TA2Metadata.RelyingParty.Contacts, "ta@foundation.example.org",
	)

	tests := []struct {
		name             string
		chain            TrustChain
		expectedMetadata *Metadata
		errExpected      bool
	}{
		{
			name:             "normal chain rp->ia2->ta2",
			chain:            chainRPIA2TA2,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      false,
		},
		{
			name:             "non-crit chain rp->ia2->ta2WithRemove",
			chain:            chainRPIA2TA2WithRemove,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      false,
		},
		{
			name:             "crit chain rp->ia2->ta2WithRemoveCrit",
			chain:            chainRPIA2TA2WithRemoveCrit,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				metadata, err := test.chain.Metadata()
				if err != nil {
					if test.errExpected {
						return
					}
					t.Error(err)
					return
				}
				if test.errExpected {
					t.Errorf("expected error, but no error returned")
					return
				}
				if !reflect.DeepEqual(metadata, test.expectedMetadata) {
					t.Errorf(
						"returned Metadata is not what we expected:\n\nReturned:\n%+v\n\nExpected:\n%+v\n\n",
						metadata, test.expectedMetadata,
					)
					return
				}
			},
		)
	}
}
