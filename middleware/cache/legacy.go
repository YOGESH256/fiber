package cache

import (
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/fieldname"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/fiber/v3/log"
)

// legacyKeyVersion is the key version before the values of the credential headers
// named in KeyHeaders were hashed in the key. Nothing reads its entries any more, but
// they still carry the credential in the key of an external Storage until they expire,
// and legacyPurge ends that for the clients that come back. Delete this file once no
// entry of that version can be left.
const legacyKeyVersion = "v4"

// maxLegacyProbes bounds the work purging adds to a middleware: past it, whatever the
// previous version stored is left to expire, as it would have without the purge.
const maxLegacyProbes = 1024

// legacyPurge deletes what the previous key version stored for a request, found by
// keying the request the way that version did. A Storage cannot list its keys, so this
// reaches the entries of the credentials that return, which is when they would have been
// read; the rest expire on their own.
type legacyPurge struct {
	m          *manager
	credential []string // the headers whose values the key hashes now
	cfg        Config   // keys as the previous version did, credential values spelled out
	probes     atomic.Int64
}

// newLegacyPurge returns nil when there is nothing to purge: an in-memory store does not
// outlive the process, and a custom KeyGenerator never had the credential in the part of
// the key this package built.
func newLegacyPurge(cfg *Config, m *manager) *legacyPurge {
	if cfg.Storage == nil || !cfg.usesDefaultKeyGenerator || len(cfg.credentialKeyHeaders) == 0 {
		return nil
	}
	previous := *cfg
	previous.credentialKeyHeaders = nil
	return &legacyPurge{m: m, cfg: previous, credential: cfg.credentialKeyHeaders}
}

// purge deletes the entry, body, Vary manifest and variant the previous version stored
// for this request, if the request sends one of the credential headers it kept in the key.
func (p *legacyPurge) purge(c fiber.Ctx, hasAuthorization bool) { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	if p == nil || p.probes.Load() >= maxLegacyProbes || !hasHeaderValue(c, p.credential) {
		return
	}
	p.probes.Add(1)

	canonical := headerlookup.Canonical(c)
	bufPtr := acquireKeyBuffer()
	buf := (*bufPtr)[:0]
	buf = append(buf, legacyKeyVersion...)
	buf = append(buf, '|')
	buf = append(buf, c.Method()...)
	buf = append(buf, '|')
	buf = appendDefaultKey(buf, c, &p.cfg)
	if hasAuthorization {
		buf = append(buf, "|auth="...)
		buf = appendAuthHash(buf, fieldname.Lines(&c.Request().Header, fiber.HeaderAuthorization, canonical))
	}
	base := string(buf)
	releaseKeyBuffer(bufPtr, buf)

	keys := []string{base, base + "_body"}
	manifestKey := base + "|vary"
	ctx := c.Context()
	if names, found, err := loadVaryManifest(ctx, p.m, manifestKey); err == nil && found {
		variant := varyKey(base, names, &c.Request().Header, canonical)
		keys = append(keys, manifestKey, variant, variant+"_body")
	}
	for _, key := range keys {
		if err := p.m.del(ctx, key); err != nil {
			log.Warnf("cache: failed to purge an entry of the previous key version: %v", err)
		}
	}
}
