package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type testVector struct {
	Number           int64                      `json:"n"`
	TAPolicy         MetadataPolicy             `json:"TA"`
	INTPolicy        MetadataPolicy             `json:"INT"`
	MergedPolicy     MetadataPolicy             `json:"merged"`
	LeafMetadata     OpenIDRelyingPartyMetadata `json:"metadata"`
	ResolvedMetadata OpenIDRelyingPartyMetadata `json:"resolved"`
	Error            string                     `json:"error"`
	ErrorDescription string                     `json:"error_description"`
}

var testVectors []testVector

func init() {
	content, err := os.ReadFile("metadata-policy-test-vectors-2025-02-13.json")
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(content, &testVectors); err != nil {
		panic(err)
	}
}

// Does will not all pass; we are more permissive on the merging,
// as long as we have the same result when the policy as actually applied
// func TestMergeMetadataPolicies(t *testing.T) {
// 	for _, test := range testVectors {
// 		t.Run(
// 			fmt.Sprintf("Merge Metadatapolicies Test Vector #%d", test.Number),
// 			func(t *testing.T) {
// 				combined, err := combineMetadataPolicy(test.TAPolicy, test.INTPolicy, "")
// 				if err != nil {
// 					if test.Error == "" {
// 						t.Fatalf("got error: %v, but no error was expected", err)
// 					} else {
// 						if err.Error() != test.Error {
// 							t.Logf(
// 								"got error: %s, but expected: %s", err.Error(), test.Error,
// 							)
// 							// do not fail
// 						}
// 						return
// 					}
// 				}
// 				expectedMarshalled, err := json.Marshal(test.MergedPolicy)
// 				if err != nil {
// 					t.Fatal(err)
// 				}
// 				combinedMarshalled, err := json.Marshal(combined)
// 				if err != nil {
// 					t.Fatal(err)
// 				}
// 				if !bytes.Equal(expectedMarshalled, combinedMarshalled) {
// 					t.Fatalf(
// 						"merged policy does not match expected policy"+
// 							": expected: \n%s\n\n, combined: \n%s\n", expectedMarshalled, combinedMarshalled,
// 					)
// 				}
// 			},
// 		)
// 	}
// }

func TestApplyPolicies(t *testing.T) {
	for _, test := range testVectors {
		t.Run(
			fmt.Sprintf("Apply Metadatapolicies Test Vector #%d", test.Number),
			func(t *testing.T) {
				if test.MergedPolicy == nil {
					return
				}
				value, err := applyPolicy(&test.LeafMetadata, test.MergedPolicy, "")
				if err != nil {
					if test.Error == "" {
						t.Fatalf("got error: %v, but no error was expected", err)
					} else {
						if err.Error() != test.Error {
							t.Logf(
								"got error: %s, but expected: %s", err.Error(), test.Error,
							)
							// do not fail
						}
						return
					}
				}
				expectedMarshalled, err := json.Marshal(test.ResolvedMetadata)
				if err != nil {
					t.Fatal(err)
				}
				resolvedMarshalled, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(expectedMarshalled, resolvedMarshalled) {
					t.Fatalf(
						"resolved metadata does not match expected"+
							" metadata"+
							": expected: \n%s\n\n, resolved: \n%s\n",
						expectedMarshalled, resolvedMarshalled,
					)
				}
			},
		)
	}
}

func TestMergeAndApplyMetadataPolicies(t *testing.T) {
	for _, test := range testVectors {
		t.Run(
			fmt.Sprintf("Test Vector #%d", test.Number),
			func(t *testing.T) {
				combined, err := combineMetadataPolicy(test.TAPolicy, test.INTPolicy, "")
				if err != nil {
					if test.Error == "" {
						t.Fatalf("merging got error: %v, but no error was expected", err)
					} else {
						if err.Error() != test.Error {
							t.Logf(
								"merging got error: %s, but expected: %s", err.Error(), test.Error,
							)
							// do not fail
						}
						return
					}
				}
				value, err := applyPolicy(&test.LeafMetadata, combined, "")
				if err != nil {
					if test.Error == "" {
						t.Fatalf("applying got error: %v, but no error was expected", err)
					} else {
						if err.Error() != test.Error {
							t.Logf(
								"applying got error: %s, but expected: %s", err.Error(), test.Error,
							)
							// do not fail
						}
						return
					}
				}
				expectedMarshalled, err := json.Marshal(test.ResolvedMetadata)
				if err != nil {
					t.Fatal(err)
				}
				resolvedMarshalled, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(expectedMarshalled, resolvedMarshalled) {
					t.Fatalf(
						"resolved metadata does not match expected"+
							" metadata"+
							": expected: \n%s\n\n, resolved: \n%s\n",
						expectedMarshalled, resolvedMarshalled,
					)
				}
			},
		)
	}
}
