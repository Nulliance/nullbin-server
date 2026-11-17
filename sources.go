//go:build !api

// Package buildinputs binds the combined binary to its frontend sources.
// These public build inputs are embedded only to reject stale bundles;
// they are never exposed by an HTTP route. API-only binaries omit them.
package buildinputs

import "embed"

// Frontend contains exactly the inputs recorded by web/build.mjs.
//
//go:embed package.json package-lock.json .npmrc tsconfig.json web/build.mjs web/frontend.mjs web/index.html all:web/src all:web/styles all:web/fonts all:web/vendor all:web/images
var Frontend embed.FS
