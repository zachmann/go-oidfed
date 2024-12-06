# Implementation of OpenID Federations for Golang

[![License](https://img.shields.io/github/license/zachmann/go-oidfed.svg)](https://github.com/zachmann/go-oidfed/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/zachmann/go-oidfed)
[![Go Report](https://goreportcard.com/badge/github.com/zachmann/go-oidfed)](https://goreportcard.com/report/github.com/zachmann/go-oidfed)
[![DeepSource](https://deepsource.io/gh/zachmann/go-oidfed.svg/?label=active+issues&show_trend=true)](https://deepsource.io/gh/zachmann/go-oidfed/?ref=repository-badge)

[//]: # ([![Release date]&#40;https://img.shields.io/github/release-date/zachmann/go-oidfed.svg&#41;]&#40;https://github.com/zachmann/go-oidfed/releases/latest&#41;)
[//]: # ([![Release version]&#40;https://img.shields.io/github/release/zachmann/go-oidfed.svg&#41;]&#40;https://github.com/zachmann/go-oidfed/releases/latest&#41;)

This repository holds a work-in-process implementation of
[OpenID Federation](https://openid.github.io/federation/main.html) in the `go` language with the goal to enable go applications to make 
use of OpenID federations.

The implementation mainly focuses on the Relying Party and Intermediate / Trust Anchor side, but not on the OP side. However, building blocks can also be utilized for OPs or other entity types.
We provide a basic library as well as a configurable and flexible fedentity to support higher level functionality. This serves as a base for our examples.
The [examples](https://github.com/zachmann/go-oidfed/tree/master/examples) directory contains example 
implementations for a [Relying Party](https://github.com/zachmann/go-oidfed/tree/master/examples/rp) and an 
[Intermediate Authority / Trust Anchor / Trust Mark Issuer](https://github.com/zachmann/go-oidfed/tree/master/examples/ta). Those serve 
as examples on how the oidfed 
library and the fedentity can be used to implement such entities;
they can be used as they are for proof of concepts;
for production usage it is strongly recommended to tweak it to your needs.

Please also refer to the README in the examples directories for further details.

### Implementation State

The library is not considered stable and some features might be missing. We encourage everybody to give feedback on 
things that are missing, not working, or weird, also suggestions for improvements and of course we are open for pull 
requests.

We try to be up-to-date with the latest version of the spec, but this might not
always be the case.


Here we try to sum up the current implementation state, (but it's very likely
that the list is not complete)

| Feature                                                                                        | Library            | Entity      |
|------------------------------------------------------------------------------------------------|--------------------|-------------|
| OpenID Configuration                                                                           | Yes                | Yes         |
| Trust Chain Building                                                                           | Yes                | When needed |
| Trust Chain Verification                                                                       | Yes                | Yes         |
| Applying Metadata Policies                                                                     | Yes                | Yes         |
| Applying Metadata from Superiors                                                               | No                 | No          |
| Support for Custom Metadata Policy Operators                                                   | Yes                | Yes         |
| Filter Trust Chains                                                                            | Yes                | Yes         |
| Configure Trust Anchors                                                                        | Yes                | Yes         |
| Set Authority Hints                                                                            | N/A                | Yes         |
| Resolve Endpoint                                                                               |                    | Yes         |
| IA Fetch Endpoint                                                                              |                    | Yes         |
| IA Listing Endpoint                                                                            |                    | Yes         |
| Trust Mark Endpoint                                                                            |                    | Yes         |
| Trust Marked Entities Endpoint                                                                 |                    | Yes         |
| Trust Mark Status Endpoint                                                                     |                    | Yes         |
| Trust Mark Owner Delegation                                                                    | Yes                | Yes         |
| Trust Mark JWT Verification                                                                    | Yes                | Yes         |
| Trust Mark JWT Verification including Delegation                                               | Yes                | Yes         |
| Trust Mark Verification through Trust Mark Status Endpoint                                     | No                 | No          |
| JWT Type Verification                                                                          | Partially          | Partially   |
| Requests using GET                                                                             |                    | Yes         |
| Requests using POST                                                                            |                    | No          |
| Client Authentication                                                                          |                    | No          |
| Automatic Client Registration                                                                  | Yes                | Yes         |
| Authorization Code Flow with Automatic Client Registration using oidc key from jwks            |                    | Yes         |
| Authorization Code Flow with Automatic Client Registration using oidc key from jwks_uri        |                    | No          |
| Authorization Code Flow with Automatic Client Registration using oidc key from signed_jwks_uri |                    | No          |
| Explicit Client Registration                                                                   | No                 | No          |
| Constraints                                                                                    | Parsed but ignored |             |
| Federation Historical Keys Endpoint                                                            | No                 | No          |
| Automatic Key Rollover                                                                         |                    | No          |
| Enrollment of Entities                                                                         |                    | Yes         |
| Configurable Checks for Enrollment                                                             |                    | Yes         |
| Custom Checks for Enrollment                                                                   |                    | Yes         |
| Request Enrollment                                                                             |                    | No          |
| Configurable Checks for Trust Mark Issuance                                                    |                    | Yes         |
| Custom Checks for Trust Mark Issuance                                                          |                    | Yes         |
| Request to become entitled for a Trust Mark                                                    |                    | No          |
| Automatically refresh trust marks in Entity Configuration                                      |                    | Yes         |



---


This work was started in and supported by the
[Geant Trust & Identity Incubator](https://connect.geant.org/trust-and-identity-incubator).

<img src="https://wiki.geant.org/download/attachments/120500419/incubator_logo.jpg" alt="Trust & Identity Incubator logo" height="75"/>
