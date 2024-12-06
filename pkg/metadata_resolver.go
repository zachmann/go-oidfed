package pkg

import (
	"encoding/json"

	"github.com/google/go-querystring/query"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal"
	"github.com/zachmann/go-oidfed/internal/http"
	"github.com/zachmann/go-oidfed/internal/jwx"
	"github.com/zachmann/go-oidfed/pkg/apimodel"
	"github.com/zachmann/go-oidfed/pkg/constants"
)

// MetadataResolver is type for resolving the metadata from a StartingEntity to
// one or multiple TrustAnchors
type MetadataResolver interface {
	Resolve(request apimodel.ResolveRequest) (*Metadata, error)
	ResolveResponsePayload(request apimodel.ResolveRequest) (ResolveResponsePayload, error)
	ResolvePossible(request apimodel.ResolveRequest) bool
}

// DefaultMetadataResolver is the default MetadataResolver used within the
// library to resolve Metadata
var DefaultMetadataResolver MetadataResolver = LocalMetadataResolver{}

// LocalMetadataResolver is a MetadataResolver that resolves trust chains and
// evaluates metadata policies to obtain the final Metadata; it does not use
// a resolve endpoint
type LocalMetadataResolver struct{}

// Resolve implements the MetadataResolver interface
func (r LocalMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, _, err := r.resolveResponsePayloadWithoutTrustMarks(req)
	return res.Metadata, err
}

func (LocalMetadataResolver) resolveResponsePayloadWithoutTrustMarks(
	req apimodel.ResolveRequest,
) (
	res ResolveResponsePayload, chain TrustChain, err error,
) {
	tr := TrustResolver{
		TrustAnchors:   NewTrustAnchorsFromEntityIDs(req.Anchor...),
		StartingEntity: req.Subject,
		Types:          req.EntityTypes,
	}
	chains := tr.ResolveToValidChains()
	chains = chains.Filter(TrustChainsFilterMinPathLength)
	if len(chains) == 0 {
		err = errors.New("no trust chain found")
		return
	}
	for _, chain = range chains {
		m, err := chain.Metadata()
		if err == nil {
			res.TrustChain = chain.Messages()
			res.Metadata = m
			return res, chain, nil
		}
	}
	err = errors.New("no trust chain with valid metadata found")
	return
}

// ResolveResponsePayload implements the MetadataResolver interface
func (r LocalMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	res ResolveResponsePayload, err error,
) {
	var chain TrustChain
	res, chain, err = r.resolveResponsePayloadWithoutTrustMarks(req)
	if err != nil {
		return
	}
	res.TrustMarks = chain[0].TrustMarks.VerifiedFederation(&chain[len(chain)-1].EntityStatementPayload)
	return
}

// ResolvePossible implements the MetadataResolver interface
func (LocalMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) bool {
	tr := TrustResolver{
		TrustAnchors:   NewTrustAnchorsFromEntityIDs(req.Anchor...),
		StartingEntity: req.Subject,
		Types:          req.EntityTypes,
	}
	chains := tr.ResolveToValidChains()
	return len(chains) > 0
}

// SimpleRemoteMetadataResolver is a MetadataResolver that utilizes a given
// ResolveEndpoint
type SimpleRemoteMetadataResolver struct {
	ResolveEndpoint string
}

// ResolveResponse returns the ResolveResponse from a response endpoint
func (r SimpleRemoteMetadataResolver) ResolveResponse(req apimodel.ResolveRequest) (
	*ResolveResponse, error,
) {
	params, err := query.Values(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	res, errRes, err := http.Get(r.ResolveEndpoint, params, nil)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		// TODO handle errors
		return nil, nil
	}
	return ParseResolveResponse(res.Body())
}

// Resolve implements the MetadataResolver interface
func (r SimpleRemoteMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponse(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

// ResolveResponsePayload implements the MetadataResolver interface
func (r SimpleRemoteMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	res, err := r.ResolveResponse(req)
	if err != nil {
		return ResolveResponsePayload{}, err
	}
	return res.ResolveResponsePayload, nil
}

// ResolvePossible implements the MetadataResolver interface
func (r SimpleRemoteMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) bool {
	res, err := r.ResolveResponse(req)
	if err != nil {
		internal.Log(err.Error())
		return false
	}
	return res != nil && res.Subject == req.Subject
}

// ParseResolveResponse parses a jwt into a ResolveResponse
func ParseResolveResponse(body []byte) (*ResolveResponse, error) {
	r, err := jwx.Parse(body)
	if err != nil {
		return nil, err
	}
	if !r.VerifyType(constants.JWTTypeResolveResponse) {
		return nil, errors.Errorf("response does not have '%s' JWT type", constants.JWTTypeResolveResponse)
	}
	var res ResolveResponse
	if err = json.Unmarshal(r.Payload(), &res); err != nil {
		return nil, err
	}
	return &res, err
}

// SmartRemoteMetadataResolver is a MetadataResolver that utilizes remote
// resolve endpoints. It will iterate through the resolve endpoints of the
// given TrustAnchors and stop if one is successful,
// if no resolve endpoint is successful, local resolving is used
type SmartRemoteMetadataResolver struct{}

// Resolve implements the MetadataResolver interface
func (r SmartRemoteMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	return res.Metadata, err
}

// ResolveResponsePayload implements the MetadataResolver interface
func (SmartRemoteMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	for _, tr := range req.Anchor {
		entityConfig, err := GetEntityConfiguration(tr)
		if err != nil {
			internal.Logf("error while obtaining entity configuration: %v", err)
			continue
		}
		var resolveEndpoint string
		if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil {
			resolveEndpoint = entityConfig.Metadata.FederationEntity.FederationResolveEndpoint
		}
		if resolveEndpoint == "" {
			continue
		}
		remoteResolver := SimpleRemoteMetadataResolver{
			ResolveEndpoint: resolveEndpoint,
		}
		res, err := remoteResolver.ResolveResponsePayload(req)
		if err != nil {
			internal.Logf("error while obtaining resolve response: %v", err)
			continue
		}
		return res, nil
	}
	return LocalMetadataResolver{}.ResolveResponsePayload(req)
}

// ResolvePossible implements the MetadataResolver interface
func (SmartRemoteMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) bool {
	for _, tr := range req.Anchor {
		entityConfig, err := GetEntityConfiguration(tr)
		if err != nil {
			internal.Logf("error while obtaining entity configuration: %v", err)
			continue
		}
		var resolveEndpoint string
		if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil {
			resolveEndpoint = entityConfig.Metadata.FederationEntity.FederationResolveEndpoint
		}
		if resolveEndpoint == "" {
			continue
		}
		remoteResolver := SimpleRemoteMetadataResolver{
			ResolveEndpoint: resolveEndpoint,
		}
		if remoteResolver.ResolvePossible(req) {
			// TODO if we have a differentiation between "no trust chain possible"
			//  and other error cases, we can rely on the "no trust chain possible"
			//  also in the negativ case
			return true
		}
	}
	return LocalMetadataResolver{}.ResolvePossible(req)
}
