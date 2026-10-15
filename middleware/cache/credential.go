package cache

import (
	"container/list"
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/fieldname"
	"github.com/gofiber/fiber/v3/internal/headerlist"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/utils/v2"
)

// credentialHeaders carry nothing but a credential. No other name counts: nothing in a
// name tells an API key from a tenant or a language.
var credentialHeaders = []string{fiber.HeaderAuthorization, fiber.HeaderCookie, fiber.HeaderProxyAuthorization, "X-API-Key", "X-Auth-Token", "X-Access-Token"}

// carriesCredential reports whether the header is one of credentialHeaders or declared
// in KeyCredentialHeaders: the one rule for the key, the Vary names and the stored Vary.
func (cfg *Config) carriesCredential(name string) bool {
	return fieldname.ContainsFold(credentialHeaders, name) || fieldname.ContainsFold(cfg.KeyCredentialHeaders, name)
}

// appendCredentials appends to dst those of names that carry a credential.
func (cfg *Config) appendCredentials(dst, names []string) []string {
	for _, name := range names {
		if cfg.carriesCredential(name) {
			dst = append(dst, name)
		}
	}
	return dst
}

// varyListsCredential is true when a Vary field value names a header that carries
// a credential: the entry then holds the response to one client's credential.
// Walked rather than parsed, so a hit allocates nothing for it.
func (cfg *Config) varyListsCredential(vary []byte) bool {
	for name := range headerlist.All(utils.UnsafeString(vary)) {
		if cfg.carriesCredential(name) {
			return true
		}
	}
	return false
}

// holdsCredentialResponse reports whether the entry a request found, stored with this
// Vary, can hold one client's response: the key is partitioned by a credential or the
// Vary names one. A custom KeyGenerator is opaque, so a declared header is not known to be
// in the key: the entry counts when the request that finds it sends one.
func (cfg *Config) holdsCredentialResponse(c fiber.Ctx, vary []byte) bool {
	// The config decides most hits before Vary is walked or a header is read.
	if len(cfg.KeyCookies) > 0 || (cfg.usesDefaultKeyGenerator && len(cfg.credentialKeyHeaders) > 0) {
		return true
	}
	return cfg.varyListsCredential(vary) || (!cfg.usesDefaultKeyGenerator && hasHeaderValue(c, cfg.credentialKeyHeaders))
}

// refusesCredential reports whether status is the origin refusing the request's
// credential (407 for a proxy's): a verdict on it, unlike a 5xx, which RFC 9111
// §4.3.3 lets a cache ride out.
func refusesCredential(status int) bool {
	return status == fiber.StatusUnauthorized ||
		status == fiber.StatusForbidden ||
		status == fiber.StatusProxyAuthRequired
}

// errorRefusesCredential is refusesCredential for a refusal returned as a *fiber.Error,
// wrapped or not; the error handler that sets its status runs above this middleware.
func errorRefusesCredential(err error) bool {
	var fiberErr *fiber.Error
	// A nil *fiber.Error held in an error matches errors.As and has no Code.
	return errors.As(err, &fiberErr) && fiberErr != nil && refusesCredential(fiberErr.Code)
}

// credentialScope is how far a refusal reaches.
type credentialScope struct {
	entry bool // the refusal ends the entry the request found
	keyed bool // the key holds the credential, so the Vary manifest is its own too
}

// scopeOf says what a refusal reaches in the entry the request found. With the default
// key it reaches the entry whoever sent the request: the key is built from the request, so
// the origin refusing a request that maps to it has stopped giving what is stored under
// it. A custom KeyGenerator's key is opaque, and a client turned away for its own reasons
// must not end an entry the others share, so there the refusal has to be a verdict on a
// credential, which the key may hold: the request carries one. Read before the handler
// runs.
func (cfg *Config) scopeOf(c fiber.Ctx, hasAuthorization bool) credentialScope { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	keyed := hasAuthorization || cfg.keyHoldsRequestCredential(c)
	return credentialScope{
		keyed: keyed,
		entry: cfg.usesDefaultKeyGenerator || keyed || cfg.requestCarriesCredential(c),
	}
}

// refusalKey is where the refusal of the request's credential is recorded: a digest of
// its values, not of a variant, so one record reaches every variant. It is empty when
// there is no record to make or read: the responses do not vary on a credential, the
// request sends none of the headers they vary on (an anonymous client has no credential
// to record the refusal under), or the key holds the credential, whose manifest a refusal
// drops.
func (cfg *Config) refusalKey(c fiber.Ctx, base string, varyNames []string, hasAuthorization bool) string { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	if hasAuthorization {
		return ""
	}
	var named [defaultVaryNames]string
	credentials := cfg.appendCredentials(named[:0], varyNames)
	if !cfg.usesDefaultKeyGenerator {
		// A custom key is opaque: the declared headers are assumed to be in it, so the
		// record follows the credential through all of its variants, whatever they vary on.
		credentials = append(credentials, cfg.KeyCredentialHeaders...)
		slices.Sort(credentials)
		credentials = slices.Compact(credentials)
	}
	if len(credentials) == 0 || cfg.keyHoldsRequestCredential(c) || !hasHeaderValue(c, credentials) {
		return ""
	}

	bufPtr := acquireKeyBuffer()
	buf := (*bufPtr)[:0]
	buf = append(buf, base...)
	buf = append(buf, "|refused"...)
	buf = appendVaryKey(buf, credentials, &c.Request().Header, headerlookup.Canonical(c))
	key := string(buf)
	releaseKeyBuffer(bufPtr, buf)
	return key
}

const (
	// minRefusalRecords is the fewest refusal records a middleware makes room for.
	minRefusalRecords = 1024

	// refusalRecordSize is what one record counts as against MaxBytes, which divided by it
	// sizes how many a middleware keeps. A record takes a few times that in memory, key
	// included, so this bounds their growth rather than their size.
	refusalRecordSize = 256
)

// refusalLimit is how many refusal records one middleware keeps at once. They are
// bookkeeping like the Vary manifest, so MaxBytes does not count them; it sizes them
// instead, and the oldest record goes first once there are more. Zero is no limit, as
// it is for MaxBytes.
func (cfg *Config) refusalLimit() int {
	if cfg.refusalRecordLimit > 0 {
		return cfg.refusalRecordLimit
	}
	if cfg.MaxBytes == 0 {
		return 0
	}
	return int(min(max(cfg.MaxBytes/refusalRecordSize, minRefusalRecords), math.MaxInt32))
}

// refusalRecords keeps the records of refused credentials, no more of them at a time
// than the limit allows, so refusing many credentials cannot grow the storage without
// bound while their records wait to expire.
type refusalRecords struct {
	cfg   *Config
	m     *manager
	keys  keyLog
	until atomic.Uint64 // the second from which the in-memory store holds none of ours
}

func newRefusalRecords(cfg *Config, m *manager) *refusalRecords {
	return &refusalRecords{cfg: cfg, m: m, keys: keyLog{limit: cfg.refusalLimit()}}
}

// mayHold reports whether a record can exist for a hit to find: a Storage may hold ones
// that were written elsewhere, the in-memory store only those this middleware wrote, until
// the last of them has expired. It reads the clock that store expires with.
func (r *refusalRecords) mayHold() bool {
	return r.cfg.Storage != nil || uint64(utils.Timestamp()) < r.until.Load()
}

// refused reports whether a refusal was recorded under key. A refusal ends only the
// entry it revalidated; the record keeps the credential's other variants, under a shared
// manifest, from being served. A storage that cannot answer counts as one: the entry is
// revalidated rather than served.
func (r *refusalRecords) refused(ctx context.Context, key string) bool {
	_, err := r.m.getRaw(ctx, key)
	if err == nil {
		return true
	}
	if errors.Is(err, errCacheMiss) {
		return false
	}
	log.Warnf("cache: failed to read the record of a refused credential: %v", err)
	return true
}

// record keeps the refusal under key for at least Expiration, and as long as the
// refused entry had left (entryExp, unix seconds, zero when unknown).
func (r *refusalRecords) record(ctx context.Context, key string, entryExp uint64) {
	retention := r.cfg.Expiration
	if now := safeUnixSeconds(r.cfg.now()); entryExp > now {
		retention = max(retention, secondsToDuration(entryExp-now))
	}
	// Raised before the write, past the whole seconds the store keeps the record, plus the
	// one its rounding adds and one for a tick between its clock read and ours.
	end := uint64(utils.Timestamp()) + uint64(retention.Seconds()) + 2
	for old := r.until.Load(); end > old; old = r.until.Load() {
		if r.until.CompareAndSwap(old, end) {
			break
		}
	}
	if err := r.m.setRaw(ctx, key, []byte{1}, retention); err != nil {
		log.Warnf("cache: failed to record the refusal of a credential: %v", err)
		return
	}
	if oldest := r.keys.add(key); oldest != "" {
		if err := r.m.del(ctx, oldest); err != nil {
			log.Warnf("cache: failed to drop the oldest record of a refused credential: %v", err)
		}
	}
}

// forget drops the record of a refusal once the origin has answered the credential again
// with a response it stores: the refusal no longer stands, and left in place the record
// would send every request of the credential to the origin until it expired.
func (r *refusalRecords) forget(ctx context.Context, key string) {
	r.keys.remove(key)
	if err := r.m.del(ctx, key); err != nil {
		log.Warnf("cache: failed to clear the record of a refused credential: %v", err)
	}
}

// keyLog remembers up to limit keys, the oldest forgotten first. With no limit nothing is
// ever forgotten, so it keeps nothing.
type keyLog struct {
	items map[string]*list.Element
	order list.List
	mu    sync.Mutex
	limit int
}

// add remembers key, and returns the oldest key it had to forget to stay within its limit.
func (l *keyLog) add(key string) string {
	if l.limit == 0 {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.items[key]; ok {
		l.order.MoveToBack(element)
		return ""
	}
	if l.items == nil {
		l.items = make(map[string]*list.Element)
	}
	l.items[key] = l.order.PushBack(key)
	if l.order.Len() <= l.limit {
		return ""
	}
	oldest, ok := l.order.Remove(l.order.Front()).(string)
	if !ok {
		return ""
	}
	delete(l.items, oldest)
	return oldest
}

// remove forgets key.
func (l *keyLog) remove(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.items[key]; ok {
		l.order.Remove(element)
		delete(l.items, key)
	}
}

// keyHoldsRequestCredential reports whether the default key holds a credential the
// request carries (a KeyCookies cookie or a credential header). A custom KeyGenerator
// is opaque, so it holds none.
func (cfg *Config) keyHoldsRequestCredential(c fiber.Ctx) bool {
	if !cfg.usesDefaultKeyGenerator {
		return false
	}
	for _, name := range cfg.KeyCookies {
		if c.Cookies(name) != "" {
			return true
		}
	}
	return hasHeaderValue(c, cfg.credentialKeyHeaders)
}

// requestCarriesCredential reports whether the request sends a value for a header that
// carries a credential, whatever the key is built from.
func (cfg *Config) requestCarriesCredential(c fiber.Ctx) bool {
	return hasHeaderValue(c, credentialHeaders) || hasHeaderValue(c, cfg.KeyCredentialHeaders)
}

// hasHeaderValue reports whether the request sends a value for any of the headers.
func hasHeaderValue(c fiber.Ctx, names []string) bool {
	canonical := headerlookup.Canonical(c)
	for _, name := range names {
		if utils.EqualFold(name, fiber.HeaderCookie) {
			// Walked in fasthttp's cookie store: asking for the Cookie field builds a
			// line from it, which costs allocations that this question does not need.
			for range c.Request().Header.Cookies() {
				return true
			}
			continue
		}
		if len(fieldname.First(&c.Request().Header, name, canonical)) > 0 {
			return true
		}
	}
	return false
}
