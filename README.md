# Implementation of OpenID Federations for Golang

[![License](https://img.shields.io/github/license/zachmann/go-oidfed.svg)](https://github.com/zachmann/go-oidfed/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/zachmann/go-oidfed)
[![Go Report](https://goreportcard.com/badge/github.com/zachmann/go-oidfed)](https://goreportcard.com/report/github.com/zachmann/go-oidfed)
[![DeepSource](https://deepsource.io/gh/zachmann/go-oidfed.svg/?label=active+issues&show_trend=true)](https://deepsource.io/gh/zachmann/go-oidfed/?ref=repository-badge)

[//]: # ([![Release date]&#40;https://img.shields.io/github/release-date/zachmann/go-oidfed.svg&#41;]&#40;https://github.com/zachmann/go-oidfed/releases/latest&#41;)
[//]: # ([![Release version]&#40;https://img.shields.io/github/release/zachmann/go-oidfed.svg&#41;]&#40;https://github.com/zachmann/go-oidfed/releases/latest&#41;)

This repository holds an implementation of
[OpenID Federation](https://openid.bitbucket.io/connect/openid-federation-1_0.html) in the `go` language with the goal to enable go applications to make 
use of OpenID federations.

The implementation mainly focuses on the Relying Party side, but can also be utilized for other entity types.
The [examples](https://github.com/zachmann/go-oidfed/tree/master/examples) directory contains example 
implementations for a [Relying Party](https://github.com/zachmann/go-oidfed/tree/master/examples/rp) and an 
[Intermediate Authority / Trust Anchor](https://github.com/zachmann/go-oidfed/tree/master/examples/ta). Those serve 
as examples, **they are by no means production ready**, but can serve as a good starting point on how the oidfed 
library can be used to implement such entities.

The library is not considered stable and some features might be missing. We encourage everybody to give feedback on 
things that are missing, not working, or weird, also suggestions for improvements and of course we are open for pull 
requests.

---


This work was started in and supported by the
[Geant Trust & Identity Incubator](https://connect.geant.org/trust-and-identity-incubator).

<img src="https://wiki.geant.org/download/attachments/120500419/incubator_logo.jpg" alt="Trust & Identity Incubator logo" height="75"/>
