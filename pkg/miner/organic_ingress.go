// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// proxyOrganic forwards one edge-authorized request (ProxyRuntime already
// verified the edge-runtime-request signature, body and nonce) byte-exact to
// the container. Every request is served the same way: any other X-Ms-*
// request header is stripped like the rest and grants nothing. Evidence about
// a response is its response receipt.
func (a *Agent) proxyOrganic(w http.ResponseWriter, req *http.Request, endpointID, rawURL string, ticket protocol.TicketV4) {
	target, err := url.Parse(rawURL)
	if err != nil {
		http.Error(w, "endpoint target invalid", http.StatusBadGateway)
		return
	}
	proxy := &httputil.ReverseProxy{
		Transport: runtimeTransport,
		// Every X-Ms-* request header, including the edge authorization, is
		// edge/agent protocol and never reaches the app.
		Rewrite: func(request *httputil.ProxyRequest) { rewriteRuntimeRequest(request, target, ticket.RouteHost) },
		ModifyResponse: func(response *http.Response) error {
			// An app-supplied X-Ms-* header is always a spoof.
			if err := sanitizeRuntimeResponse(response); err != nil {
				return err
			}
			// The receipt header digest covers the application response
			// headers as sent.
			if tap := receiptTapFrom(response.Request.Context()); tap != nil {
				tap.setHeaderDigest(response.Header.Clone())
			}
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
			switch {
			case errors.Is(proxyErr, errRuntimeResponseTooLarge):
				http.Error(writer, "runtime response exceeds the miner limit", http.StatusBadGateway)
			default:
				http.Error(writer, "runtime unavailable", http.StatusBadGateway)
			}
		},
		FlushInterval: -1,
	}
	proxy.ServeHTTP(w, req)
}
