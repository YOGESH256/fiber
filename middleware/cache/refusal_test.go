package cache

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// credentialPartition is one way the cache can tell sessions apart, and how the
// fixture app is sent and reads the session for it.
type credentialPartition struct {
	configure    func(*Config)               // makes the cache tell sessions apart
	send         func(*http.Request, string) // puts a session on a request
	read         func(fiber.Ctx) string      // takes it off again
	vary         string                      // the Vary the app adds, if any
	cacheControl string                      // the Cache-Control the app adds, if any
}

func sendCookie(req *http.Request, session string) {
	req.Header.Set(fiber.HeaderCookie, "session="+session)
}

func readCookie(c fiber.Ctx) string { return c.Cookies("session") }

func sendBearer(req *http.Request, session string) {
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+session)
}

func readBearer(c fiber.Ctx) string {
	return strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
}

// headerPartition carries the session in the named request header.
func headerPartition(name string, configure func(*Config)) credentialPartition {
	return credentialPartition{
		configure: configure,
		send:      func(req *http.Request, session string) { req.Header.Set(name, session) },
		read:      func(c fiber.Ctx) string { return c.Get(name) },
	}
}

var credentialPartitions = map[string]credentialPartition{
	"keyCookies": {
		configure: func(cfg *Config) { cfg.KeyCookies = []string{"session"} },
		send:      sendCookie,
		read:      readCookie,
	},
	"varyCookie": {send: sendCookie, read: readCookie, vary: fiber.HeaderCookie},
	"authorization": {
		send: sendBearer,
		read: readBearer,
		// A request carrying Authorization is stored only when the response says a
		// shared cache may.
		cacheControl: "public, max-age=60",
	},
	// An API key, which the cache takes for a credential by name.
	"apiKey": headerPartition("X-Api-Key", func(cfg *Config) { cfg.KeyHeaders = []string{"X-Api-Key"} }),
	// A header of the app's own, which it declares one in KeyCredentialHeaders.
	"credentialHeader": headerPartition("X-Company-Token", func(cfg *Config) { cfg.KeyCredentialHeaders = []string{"X-Company-Token"} }),
	// Varies on a header the cache recognizes, whatever the key is built from.
	"varyApiKey": func() credentialPartition {
		p := headerPartition("X-Api-Key", nil)
		p.vary = "X-Api-Key"
		return p
	}(),
	// A key of the app's own, built from a header it declares to carry a credential.
	"customKey": headerPartition("X-Company-Token", func(cfg *Config) {
		cfg.KeyCredentialHeaders = []string{"X-Company-Token"}
		cfg.KeyGenerator = func(c fiber.Ctx) string { return c.Path() + "|" + c.Get("X-Company-Token") }
	}),
	// Headers nothing in their name or in the config marks as a credential.
	"tenant":       headerPartition("X-Tenant", func(cfg *Config) { cfg.KeyHeaders = []string{"X-Tenant"} }),
	"customHeader": headerPartition("X-Session", func(cfg *Config) { cfg.KeyHeaders = []string{"X-Session"} }),
	"customVary": func() credentialPartition {
		p := headerPartition("X-Session", nil)
		p.vary = "X-Session"
		return p
	}(),
}

// credentialFixture is an app behind the cache that answers per session: valid sessions
// get a body naming them and their X-Variant, any other is handed to refuse.
type credentialFixture struct {
	app       *fiber.App
	t         *testing.T
	probe     *accountingProbe
	ended     sync.Map
	partition credentialPartition
	calls     atomic.Int32
}

type credentialOptions struct {
	custom fiber.Storage         // used instead of storage when set
	refuse func(fiber.Ctx) error // the answer to a session that is not valid, a bare 401 when nil
	// clock and expiration push an entry past its lifetime while storage still holds it.
	clock *testClock
	// beforeRefusal runs inside the origin before it refuses a session, as another
	// request would meanwhile.
	beforeRefusal func(*credentialFixture)
	partition     string   // a key of credentialPartitions
	storage       string   // memory or external
	vary          string   // a Vary the served answer carries besides the partition's
	valid         []string // the sessions the app answers, "a" and "b" when nil
	expiration    time.Duration
	recordCap     int // how many refusal records the cache keeps, derived from MaxBytes when zero
	// invalidateEnded has CacheInvalidator report the sessions the app has ended.
	invalidateEnded bool
}

// The axes the refusal scenarios run over: how a client reloads, and what refuses it.
var (
	reloadForms     = []string{"max-age=0", "no-cache"}
	refusalStatuses = []int{fiber.StatusUnauthorized, fiber.StatusForbidden, fiber.StatusProxyAuthRequired}
)

func newCredentialFixture(t *testing.T, opts *credentialOptions) *credentialFixture {
	t.Helper()

	partition, ok := credentialPartitions[opts.partition]
	require.True(t, ok, "unknown partition %q", opts.partition)

	valid := opts.valid
	if valid == nil {
		valid = []string{"a", "b"}
	}
	refuse := opts.refuse
	if refuse == nil {
		refuse = refusal(fiber.StatusUnauthorized, "bare")
	}

	f := &credentialFixture{t: t, probe: &accountingProbe{}, partition: partition}
	// A byte limit turns on the heap accounting a purge has to keep honest.
	cfg := Config{MaxBytes: 1 << 20, accounting: f.probe.record, Expiration: opts.expiration, refusalRecordLimit: opts.recordCap}
	if opts.clock != nil {
		cfg.clock = opts.clock.Now
	}
	if partition.configure != nil {
		partition.configure(&cfg)
	}
	cfg.Storage = opts.custom
	if cfg.Storage == nil {
		cfg.Storage = storageOf(opts.storage)
	}
	if opts.invalidateEnded {
		cfg.CacheInvalidator = func(c fiber.Ctx) bool {
			_, ended := f.ended.Load(partition.read(c))
			return ended
		}
	}

	f.app = fiber.New()
	f.app.Use(New(cfg))
	f.app.Get("/account", func(c fiber.Ctx) error {
		f.calls.Add(1)
		session := partition.read(c)
		if _, ended := f.ended.Load(session); ended || !slices.Contains(valid, session) {
			if opts.beforeRefusal != nil {
				opts.beforeRefusal(f)
			}
			return refuse(c)
		}

		vary := slices.DeleteFunc([]string{partition.vary, opts.vary}, func(name string) bool { return name == "" })
		if len(vary) > 0 {
			c.Set(fiber.HeaderVary, strings.Join(vary, ", "))
		}
		if partition.cacheControl != "" {
			c.Set(fiber.HeaderCacheControl, partition.cacheControl)
		}
		return c.SendString(accountBody(session, c.Get("X-Variant")))
	})
	return f
}

// get asks for the account as session, which is sent the way the partition
// carries it; an empty session sends nothing.
func (f *credentialFixture) get(session, variant, cacheControl string) reply {
	f.t.Helper()

	req := httptest.NewRequest(fiber.MethodGet, "/account", http.NoBody)
	if session != "" {
		f.partition.send(req, session)
	}
	if variant != "" {
		req.Header.Set("X-Variant", variant)
	}
	if cacheControl != "" {
		req.Header.Set(fiber.HeaderCacheControl, cacheControl)
	}
	return doRequest(f.t, f.app, req)
}

// requireHit asserts the session is answered from the cache with its own data.
func (f *credentialFixture) requireHit(session, variant string) {
	f.t.Helper()

	got := f.get(session, variant, "")
	require.Equal(f.t, fiber.StatusOK, got.status)
	require.Equal(f.t, accountBody(session, variant), got.body)
	require.Equal(f.t, cacheHit, got.cache)
}

// warm sends each session's request for each variant (one without a variant when none
// is named) and asserts that every one reached the origin, which stored its answer.
func (f *credentialFixture) warm(sessions []string, variants ...string) {
	f.t.Helper()

	if len(variants) == 0 {
		variants = []string{""}
	}
	for _, session := range sessions {
		for _, variant := range variants {
			got := f.get(session, variant, "")
			require.Equal(f.t, fiber.StatusOK, got.status)
			require.Equal(f.t, accountBody(session, variant), got.body)
			require.Equal(f.t, cacheMiss, got.cache)
		}
	}
}

// requireRefused asserts a request of session "a", the one the app has ended, reached
// the origin, which refused it with status, and returns what came back.
func (f *credentialFixture) requireRefused(status int, variant, cacheControl string) reply {
	f.t.Helper()

	return f.requireRefusedAs(status, "a", variant, cacheControl)
}

// requireRefusedAs is requireRefused for another session.
func (f *credentialFixture) requireRefusedAs(status int, session, variant, cacheControl string) reply {
	f.t.Helper()

	calls := f.calls.Load()
	got := f.get(session, variant, cacheControl)
	require.Equal(f.t, status, got.status, "a refused credential was answered from the cache")
	require.NotContains(f.t, got.body, "ACCOUNT")
	require.Equal(f.t, calls+1, f.calls.Load(), "a refused credential must reach the origin")
	return got
}

func accountBody(session, variant string) string {
	return "ACCOUNT: data of " + session + "/" + variant
}

// refusal answers with status, naming directive on the response: "bare" for
// none, "VaryStar" for Vary: *, anything else as a Cache-Control.
func refusal(status int, directive string) func(fiber.Ctx) error {
	return func(c fiber.Ctx) error {
		switch directive {
		case "bare":
		case "VaryStar":
			c.Set(fiber.HeaderVary, "*")
		default:
			c.Set(fiber.HeaderCacheControl, directive)
		}
		return c.SendStatus(status)
	}
}

// refusingAfter refuses with a 401 once strip has taken the credential out of the
// request, as a handler that clears a session it has just rejected would.
func refusingAfter(strip func(*fasthttp.RequestHeader)) func(fiber.Ctx) error {
	return func(c fiber.Ctx) error {
		strip(&c.Request().Header)
		return c.SendStatus(fiber.StatusUnauthorized)
	}
}

// A reload answered 401, 403 or 407 refuses the credential its entry was stored under:
// the entry must go and other credentials' entries stay, for a bare refusal as for one
// carrying any directive, and whether or not the cache takes the header for a credential.
func Test_Cache_RejectedCredentialDropsEntry(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "varyCookie", "varyApiKey", "authorization", "customHeader", "customVary"} {
		for _, storage := range storageKinds {
			for _, reload := range reloadForms {
				for _, status := range refusalStatuses {
					for _, directive := range []string{"bare", "private", "no-store", "no-cache", "VaryStar"} {
						t.Run(fmt.Sprintf("%s/%s/%s/%d/%s", partition, storage, reload, status, directive), func(t *testing.T) {
							t.Parallel()

							f := newCredentialFixture(t, &credentialOptions{
								partition: partition,
								storage:   storage,
								refuse:    refusal(status, directive),
							})

							bodySize := uint(len(accountBody("a", "")))
							f.warm([]string{"a", "b"})
							f.requireHit("a", "")
							require.Equal(t, 2*bodySize, f.probe.counted())
							require.Equal(t, 2, f.probe.nodes())

							// A refusal that found no entry of its own purges nothing.
							for _, cacheControl := range []string{"", reload} {
								got := f.get("stranger", "", cacheControl)
								require.Equal(t, status, got.status)
								require.Equal(t, cacheUnreachable, got.cache)
							}
							f.requireHit("b", "")
							f.requireHit("a", "")
							require.Equal(t, 2*bodySize, f.probe.counted())
							require.Equal(t, 2, f.probe.nodes())

							// The app ends the session; the reload reaches the origin.
							f.ended.Store("a", true)
							got := f.get("a", "", reload)
							require.Equal(t, status, got.status)
							require.Equal(t, cacheUnreachable, got.cache)

							// The same credential must now meet the origin again, not the old body.
							got = f.requireRefused(status, "", "")
							require.Equal(t, cacheUnreachable, got.cache)

							// The purge gave back exactly the refused entry's accounting.
							require.Equal(t, bodySize, f.probe.counted())
							require.Equal(t, 1, f.probe.nodes())

							// Only the refused credential's entry went.
							f.requireHit("b", "")
						})
					}
				}
			}
		}
	}
}

// A handler that refuses by returning the error (fiber.ErrUnauthorized) writes no
// status for the cache to see, yet the refusal still ends the entry; an error
// that says nothing about the credential does not.
func Test_Cache_RejectedCredentialReturnedAsError(t *testing.T) {
	t.Parallel()

	answers := []struct {
		err    error
		name   string
		status int
		drops  bool
	}{
		{name: "401", err: fiber.ErrUnauthorized, status: fiber.StatusUnauthorized, drops: true},
		{name: "403", err: fiber.ErrForbidden, status: fiber.StatusForbidden, drops: true},
		{name: "407", err: fiber.ErrProxyAuthRequired, status: fiber.StatusProxyAuthRequired, drops: true},
		{name: "wrapped 401", err: fmt.Errorf("session expired: %w", fiber.ErrUnauthorized), status: fiber.StatusUnauthorized, drops: true},
		{name: "503", err: fiber.ErrServiceUnavailable, status: fiber.StatusServiceUnavailable},
		{name: "429", err: fiber.ErrTooManyRequests, status: fiber.StatusTooManyRequests},
		{name: "plain error", err: errors.New("session store unreachable"), status: fiber.StatusInternalServerError},
	}

	for _, partition := range []string{"keyCookies", "varyCookie", "authorization"} {
		for _, storage := range storageKinds {
			for _, reload := range reloadForms {
				for _, answer := range answers {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", partition, storage, reload, answer.name), func(t *testing.T) {
						t.Parallel()

						f := newCredentialFixture(t, &credentialOptions{
							partition: partition,
							storage:   storage,
							refuse:    func(fiber.Ctx) error { return answer.err },
						})
						f.warm([]string{"a", "b"})

						f.ended.Store("a", true)
						require.Equal(t, answer.status, f.get("a", "", reload).status)

						if answer.drops {
							f.requireRefused(answer.status, "", "")
						} else {
							calls := f.calls.Load()
							f.requireHit("a", "")
							require.Equal(t, calls, f.calls.Load())
						}

						f.requireHit("b", "")
					})
				}
			}
		}
	}
}

// A refusal ends the entry it revalidated, and takes the credential's other variants
// along when the Vary manifest is its own, that is when the key holds the credential.
// A manifest shared with other clients stays, and with it their entries.
func Test_Cache_RejectedCredentialDropsItsVariants(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		refuse      func(fiber.Ctx) error // the refusal, a bare 401 when nil
		name        string
		partition   string
		anonymous   bool
		siblingKept bool // the credential's other variant stays, its manifest being shared
	}{
		{name: "KeyCookies", partition: "keyCookies"},
		{name: "Authorization", partition: "authorization"},
		// The manifest is shared by every session, so it stays; the refusal is recorded
		// instead, and the refused session's other variant is revalidated, not served.
		{name: "Vary Cookie", partition: "varyCookie"},
		{name: "Vary X-API-Key", partition: "varyApiKey"},
		{name: "API key header", partition: "apiKey"},
		{name: "header declared in KeyCredentialHeaders", partition: "credentialHeader"},
		// A custom key is opaque, so the declared header is taken to be in it: the record
		// follows the credential through variants that vary on nothing.
		{name: "custom KeyGenerator, declared header", partition: "customKey"},
		// Nothing in the name tells a tenant from a credential, so the manifest is shared:
		// the refused entry goes and its siblings stay.
		{name: "tenant header, not a credential", partition: "tenant", siblingKept: true},
		// An undeclared header is no credential either, with or without a directive on
		// the refusal.
		{name: "undeclared header, bare refusal", partition: "customHeader", siblingKept: true},
		{
			name: "undeclared header, private refusal", partition: "customHeader", siblingKept: true,
			refuse: refusal(fiber.StatusUnauthorized, "private"),
		},
		// Directives change nothing about the siblings: the other sessions keep theirs.
		{
			name: "Vary Cookie, no-store refusal", partition: "varyCookie",
			refuse: refusal(fiber.StatusUnauthorized, "no-store"),
		},
		{
			name: "Vary X-API-Key, private refusal", partition: "varyApiKey",
			refuse: refusal(fiber.StatusUnauthorized, "private"),
		},
		// A Vary on a header nothing marks as a credential gets no record: the cache
		// cannot tell the header from a tenant, and the sibling ages out.
		{name: "undeclared Vary, bare refusal", partition: "customVary", siblingKept: true},
		{
			name: "undeclared Vary, private refusal", partition: "customVary", siblingKept: true,
			refuse: refusal(fiber.StatusUnauthorized, "private"),
		},
		// The entry every client without the cookie shares goes; its sibling stays.
		{name: "no credential in the key", partition: "keyCookies", anonymous: true, siblingKept: true},
		// The key is decided before the handler runs, so clearing the credential cannot change it.
		{
			name: "KeyCookies, cookie cleared by the handler", partition: "keyCookies",
			refuse: refusingAfter(func(h *fasthttp.RequestHeader) { h.DelAllCookies() }),
		},
		{
			name: "Authorization, header cleared by the handler", partition: "authorization",
			refuse: refusingAfter(func(h *fasthttp.RequestHeader) { h.Del(fiber.HeaderAuthorization) }),
		},
	}

	for _, storage := range storageKinds {
		for _, scenario := range scenarios {
			t.Run(storage+"/"+scenario.name, func(t *testing.T) {
				t.Parallel()

				refused, other := "a", "b"
				var valid []string
				if scenario.anonymous {
					// No cookie is sent, so the key is shared by every client without one.
					refused, valid = "", []string{"", "b"}
				}
				f := newCredentialFixture(t, &credentialOptions{
					partition: scenario.partition,
					storage:   storage,
					vary:      "X-Variant",
					valid:     valid,
					refuse:    scenario.refuse,
				})
				f.warm([]string{refused, other}, "one", "two")

				f.ended.Store(refused, true)
				got := f.get(refused, "one", "no-cache")
				require.Equal(t, fiber.StatusUnauthorized, got.status)
				require.Equal(t, cacheUnreachable, got.cache)

				got = f.get(refused, "one", "")
				require.Equal(t, fiber.StatusUnauthorized, got.status, "the refused variant was answered from the cache")

				got = f.get(refused, "two", "")
				if scenario.siblingKept {
					require.Equal(t, cacheHit, got.cache)
				} else {
					require.Equal(t, fiber.StatusUnauthorized, got.status, "a variant of the refused credential was answered from the cache")
				}

				for _, variant := range []string{"one", "two"} {
					f.requireHit(other, variant)
				}
			})
		}
	}
}

// The recipe in the docs: a CacheInvalidator that reports the sessions the app has ended,
// beside KeyCookies or a Vary on Cookie. A session ended without its client reloading is cut
// off at once, every variant of it, even for a request that accepts stale entries.
func Test_Cache_InvalidatorCutsOffEndedSession(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "varyCookie"} {
		for _, storage := range storageKinds {
			for _, request := range []struct{ name, cacheControl string }{{"plain", ""}, {"max-stale", "max-stale"}} {
				t.Run(partition+"/"+storage+"/"+request.name, func(t *testing.T) {
					t.Parallel()

					f := newCredentialFixture(t, &credentialOptions{
						partition:       partition,
						storage:         storage,
						vary:            "X-Variant",
						invalidateEnded: true,
					})
					variants := []string{"one", "two"}
					f.warm([]string{"a", "b"}, variants...)
					for _, variant := range variants {
						f.requireHit("a", variant)
					}

					f.ended.Store("a", true)
					for _, variant := range variants {
						f.requireRefused(fiber.StatusUnauthorized, variant, request.cacheControl)
					}

					for _, variant := range variants {
						f.requireHit("b", variant)
					}
				})
			}
		}
	}
}

// refusalStorage counts the reads and writes of refusal records, which are the keys
// naming "|refused|", can fail the reads, and says how many records it holds.
type refusalStorage struct {
	*failingCacheStorage
	reads  atomic.Int32
	writes atomic.Int32
	fail   atomic.Bool
}

func newRefusalStorage() *refusalStorage {
	return &refusalStorage{failingCacheStorage: newFailingCacheStorage()}
}

func (s *refusalStorage) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	if strings.Contains(key, "|refused|") {
		s.writes.Add(1)
	}
	return s.failingCacheStorage.SetWithContext(ctx, key, val, exp)
}

// records is how many refusal records the storage holds.
func (s *refusalStorage) records() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for key := range s.data {
		if strings.Contains(key, "|refused|") {
			n++
		}
	}
	return n
}

func (s *refusalStorage) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	if strings.Contains(key, "|refused|") {
		s.reads.Add(1)
		if s.fail.Load() {
			return nil, errors.New("storage unavailable")
		}
	}
	return s.failingCacheStorage.GetWithContext(ctx, key)
}

// A refused session's other variants stay out whatever the other sessions do to the
// URL: a miss of theirs stores the Vary manifest again.
func Test_Cache_RefusedCredentialStaysOutWhileOthersMiss(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"varyCookie", "varyApiKey"} {
		for _, storage := range storageKinds {
			for _, directive := range []string{"bare", "no-store"} {
				t.Run(partition+"/"+storage+"/"+directive, func(t *testing.T) {
					t.Parallel()

					f := newCredentialFixture(t, &credentialOptions{
						partition: partition,
						storage:   storage,
						vary:      "X-Variant",
						refuse:    refusal(fiber.StatusUnauthorized, directive),
					})
					f.warm([]string{"a", "b"}, "one", "two")

					f.ended.Store("a", true)
					require.Equal(t, fiber.StatusUnauthorized, f.get("a", "one", "no-cache").status)

					// Another session misses on a variant of its own, which stores the manifest again.
					require.Equal(t, cacheMiss, f.get("b", "three", "").cache)

					f.requireRefused(fiber.StatusUnauthorized, "two", "")

					for _, variant := range []string{"one", "two", "three"} {
						f.requireHit("b", variant)
					}
				})
			}
		}
	}
}

// Only a response that varies on a credential costs the read of a refusal record, and
// only for a client that sends one the key does not hold: an anonymous client has none
// to have been refused, and for a keyed credential the refusal drops the manifest instead.
func Test_Cache_RefusalRecordIsReadOnlyForCredentialVary(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		partition string
		vary      string
		reads     int32 // per hit
		anonymous bool
	}{
		{name: "no Vary", partition: "tenant"},
		{name: "Vary: X-Variant", partition: "tenant", vary: "X-Variant"},
		{name: "Vary: Cookie", partition: "varyCookie", reads: 1},
		{name: "Vary: Cookie, X-Variant", partition: "varyCookie", vary: "X-Variant", reads: 1},
		{name: "Vary: X-API-Key", partition: "varyApiKey", reads: 1},
		{name: "Vary: Cookie, no cookie sent", partition: "varyCookie", anonymous: true},
		{name: "Vary: X-API-Key, no key sent", partition: "varyApiKey", anonymous: true},
		{name: "Vary: Cookie, the key holds the cookie", partition: "keyCookies", vary: "Cookie"},
		{name: "Vary: Authorization, the key holds the credential", partition: "authorization", vary: "Authorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			session := "a"
			if tc.anonymous {
				session = ""
			}
			storage := newRefusalStorage()
			f := newCredentialFixture(t, &credentialOptions{
				partition: tc.partition,
				custom:    storage,
				vary:      tc.vary,
				valid:     []string{session},
			})
			require.Equal(t, cacheMiss, f.get(session, "", "").cache)
			require.Zero(t, storage.reads.Load(), "a miss has nothing to check")

			for range 3 {
				require.Equal(t, cacheHit, f.get(session, "", "").cache)
			}
			require.Equal(t, 3*tc.reads, storage.reads.Load())
		})
	}
}

// A storage that cannot say whether the credential was refused is not a reason to
// serve it: the entry is revalidated instead.
func Test_Cache_UnreadableRefusalRecordRevalidates(t *testing.T) {
	t.Parallel()

	storage := newRefusalStorage()
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		custom:    storage,
		valid:     []string{"a"},
	})
	require.Equal(t, cacheMiss, f.get("a", "", "").cache)
	require.Equal(t, cacheHit, f.get("a", "", "").cache)

	storage.fail.Store(true)
	calls := f.calls.Load()
	got := f.get("a", "", "")
	require.Equal(t, cacheMiss, got.cache)
	require.Equal(t, calls+1, f.calls.Load(), "the entry must reach the origin")
}

// A client that sends no credential is refused like any other: its reload ends the entry
// it revalidated, the one every client with the same key shares. No record of the refusal
// is made or read, since there is no credential to record it under; a request that found
// no entry of its own ends nothing, and the entries of the sessions that do send one stay.
func Test_Cache_RefusedAnonymousClientEndsTheEntryItRevalidated(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"varyCookie", "varyApiKey", "tenant", "customHeader", "customVary"} {
		for _, storage := range storageKinds {
			for _, reload := range reloadForms {
				for _, status := range refusalStatuses {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", partition, storage, reload, status), func(t *testing.T) {
						t.Parallel()

						backing := newRefusalStorage()
						opts := &credentialOptions{partition: partition, valid: []string{"", "a"}, refuse: refusal(status, "bare")}
						if storage == "external" {
							opts.custom = backing
						}
						f := newCredentialFixture(t, opts)
						f.warm([]string{"", "a"})
						f.requireHit("", "")

						// A refusal that found no entry of its own ends nothing.
						f.requireRefusedAs(status, "stranger", "", reload)
						f.requireHit("", "")

						// The app starts turning away clients that send no credential.
						f.ended.Store("", true)
						f.requireRefusedAs(status, "", "", reload)

						// The entry went with the refusal, so the next request asks the origin again.
						f.requireRefusedAs(status, "", "", "")
						require.Zero(t, backing.writes.Load(), "an anonymous client has no credential to record a refusal of")
						require.Zero(t, backing.reads.Load(), "an anonymous client has no record to be checked against")

						// Only the entry the refusal revalidated went.
						f.requireHit("a", "")
					})
				}
			}
		}
	}
}

// A refusal that no longer stands is forgotten: once the origin answers the credential
// again with a response it stores, the credential's entries are served without a trip to
// the origin, and the record of the refusal is gone.
func Test_Cache_RefusedCredentialRecoversWhenAccepted(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"varyCookie", "varyApiKey"} {
		t.Run(partition, func(t *testing.T) {
			t.Parallel()

			storage := newRefusalStorage()
			f := newCredentialFixture(t, &credentialOptions{
				partition: partition,
				custom:    storage,
				vary:      "X-Variant",
			})
			f.warm([]string{"a", "b"}, "one", "two")

			f.ended.Store("a", true)
			f.requireRefused(fiber.StatusUnauthorized, "one", "no-cache")
			require.Equal(t, 1, storage.records(), "the refusal is recorded")

			// The session is granted again. Its other variant is still stored, but the record
			// sends it to the origin once, which stores the answer and ends the record.
			f.ended.Delete("a")
			calls := f.calls.Load()
			require.Equal(t, cacheMiss, f.get("a", "two", "").cache)
			require.Equal(t, calls+1, f.calls.Load(), "the record must send the entry to the origin")
			require.Zero(t, storage.records(), "the record of a refusal that no longer stands goes")

			f.requireHit("a", "two")
			require.Equal(t, cacheMiss, f.get("a", "one", "").cache, "the refused entry was dropped")
			f.requireHit("a", "one")
			f.requireHit("b", "one")
		})
	}
}

// A refusal that lands after a concurrent request stored a replacement still takes the
// credential's entries out of reach: the replacement may be an answer the credential has
// since stopped getting.
func Test_Cache_RefusalOutlivesAConcurrentReplacement(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "authorization", "varyCookie", "varyApiKey"} {
		for _, storage := range storageKinds {
			t.Run(partition+"/"+storage, func(t *testing.T) {
				t.Parallel()

				var armed atomic.Bool
				f := newCredentialFixture(t, &credentialOptions{
					partition: partition,
					storage:   storage,
					vary:      "X-Variant",
					beforeRefusal: func(f *credentialFixture) {
						if !armed.CompareAndSwap(true, false) {
							return
						}
						// Another request of the session, answered before it ended, stores its
						// response while this one is at the origin.
						f.ended.Delete("a")
						require.Equal(f.t, cacheMiss, f.get("a", "one", "max-age=0").cache)
						f.ended.Store("a", true)
					},
				})
				f.warm([]string{"a", "b"}, "one", "two")

				f.ended.Store("a", true)
				armed.Store(true)
				require.Equal(t, fiber.StatusUnauthorized, f.get("a", "one", "no-cache").status)
				require.False(t, armed.Load(), "the replacement was never stored")

				// Neither the replacement nor the other variant is served to the ended session.
				f.requireRefused(fiber.StatusUnauthorized, "one", "")
				f.requireRefused(fiber.StatusUnauthorized, "two", "")
				f.requireHit("b", "one")
			})
		}
	}
}

// A refusal is recorded only for a credential that has an entry, however many other
// credentials are refused, so the records cannot outnumber the entries they guard.
func Test_Cache_RefusalsOfUnknownCredentialsWriteNoRecords(t *testing.T) {
	t.Parallel()

	storage := newRefusalStorage()
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		custom:    storage,
		valid:     []string{"a"},
	})
	require.Equal(t, cacheMiss, f.get("a", "", "").cache)

	for i := range 50 {
		got := f.get(fmt.Sprintf("stranger-%d", i), "", "no-cache")
		require.Equal(t, fiber.StatusUnauthorized, got.status)
	}
	require.Zero(t, storage.writes.Load(), "a credential with no entry got a record")
	require.Zero(t, storage.records())

	// The one credential that has an entry gets one, refused again and again.
	f.ended.Store("a", true)
	for range 3 {
		require.Equal(t, fiber.StatusUnauthorized, f.get("a", "", "no-cache").status)
	}
	require.Equal(t, int32(1), storage.writes.Load())
	require.Equal(t, 1, storage.records())
}

// A handler that fails for a request that found an entry leaves the cache as it was: the
// error reaches the client unchanged and the entry keeps being served.
func Test_Cache_HandlerErrorKeepsTheEntry(t *testing.T) {
	t.Parallel()

	for _, storage := range storageKinds {
		t.Run(storage, func(t *testing.T) {
			t.Parallel()

			app := fiber.New()
			app.Use(New(Config{Storage: storageOf(storage)}))
			app.Get("/", func(c fiber.Ctx) error {
				if c.Get("X-Fail") == "1" {
					return fiber.ErrServiceUnavailable
				}
				return c.SendString("PUBLIC")
			})

			require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
			for _, reload := range []string{"no-cache", "max-age=0"} {
				got := getRoot(t, app, map[string]string{"X-Fail": "1", fiber.HeaderCacheControl: reload})
				require.Equal(t, fiber.StatusServiceUnavailable, got.status)
			}
			got := getRoot(t, app, nil)
			require.Equal(t, cacheHit, got.cache)
			require.Equal(t, "PUBLIC", got.body)
		})
	}
}

// The refusal records one middleware keeps are bounded: past the limit the oldest goes,
// and the storage never holds more of them than that.
func Test_Cache_RefusalRecordsAreBounded(t *testing.T) {
	t.Parallel()

	const limit = 2
	storage := newRefusalStorage()
	sessions := []string{"s1", "s2", "s3", "s4"}
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		custom:    storage,
		vary:      "X-Variant",
		valid:     append([]string{"b"}, sessions...),
		recordCap: limit,
	})
	f.warm(append([]string{"b"}, sessions...), "one", "two")

	for i, session := range sessions {
		f.ended.Store(session, true)
		f.requireRefusedAs(fiber.StatusUnauthorized, session, "one", "no-cache")
		require.LessOrEqual(t, storage.records(), limit, "after %d refusals", i+1)
	}
	require.Equal(t, limit, storage.records())

	// The most recent refusals are still held, so those sessions' other variants are not served.
	for _, session := range sessions[len(sessions)-limit:] {
		f.requireRefusedAs(fiber.StatusUnauthorized, session, "two", "")
	}
	f.requireHit("b", "one")
	f.requireHit("b", "two")
}

// An entry holding a credential's response is never served stale: the storage
// keeps it past its lifetime, so max-stale would otherwise extend it.
func Test_Cache_CredentialKeyedEntryIgnoresMaxStale(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name      string
		partition string
		stale     bool // the expired entry is still served: nothing ties it to a credential
	}{
		{name: "KeyCookies", partition: "keyCookies"},
		{name: "Vary Cookie", partition: "varyCookie"},
		{name: "Vary X-API-Key", partition: "varyApiKey"},
		{name: "Authorization", partition: "authorization"},
		{name: "API key header named in KeyHeaders", partition: "apiKey"},
		{name: "header declared in KeyCredentialHeaders", partition: "credentialHeader"},
		{name: "tenant header, not a credential", partition: "tenant", stale: true},
	}

	for _, storage := range storageKinds {
		for _, maxStale := range []string{"max-stale", "max-stale=3600"} {
			for _, scenario := range scenarios {
				t.Run(storage+"/"+maxStale+"/"+scenario.name, func(t *testing.T) {
					t.Parallel()

					clock := newTestClock(time.Unix(1_700_000_000, 0))
					f := newCredentialFixture(t, &credentialOptions{
						partition:  scenario.partition,
						storage:    storage,
						clock:      clock,
						expiration: time.Minute,
					})
					f.warm([]string{"a", "b"})

					// Past the entry's lifetime, well inside what the storage keeps.
					clock.Add(2 * time.Minute)
					f.ended.Store("a", true)
					if scenario.stale {
						calls := f.calls.Load()
						got := f.get("a", "", maxStale)
						require.Equal(t, fiber.StatusOK, got.status)
						require.Equal(t, accountBody("a", ""), got.body)
						require.Equal(t, cacheHit, got.cache)
						require.Equal(t, calls, f.calls.Load())
						return
					}
					f.requireRefused(fiber.StatusUnauthorized, "", maxStale)
				})
			}
		}
	}
}

// A refusal ends the entry it revalidated, also when no credential is keyed on it: the entry
// is the one every client with the same key shares, and the origin has stopped giving it to
// a request that maps to it. The exception is a custom KeyGenerator, whose key the middleware
// cannot see into: a client that sends no credential and is turned away for its own reasons,
// an IP or geo rule say, must not end the entry the others share, while one that sends a
// credential may be the one the key holds.
func Test_Cache_RefusalEndsTheEntryUnlessACustomKeyHasNoCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		blocked   map[string]string // what the client the app refuses sends besides X-Blocked
		name      string
		directive string // the Cache-Control the refusal carries, if any
		cfg       Config
		kept      bool
	}{
		{name: "default key"},
		{name: "default key, a cookie the key does not hold", blocked: map[string]string{"Cookie": "sid=1"}},
		{name: "KeyHeaders naming a tenant", cfg: Config{KeyHeaders: []string{"X-Tenant"}}},
		{name: "KeyCookies the request does not carry", cfg: Config{KeyCookies: []string{"session"}}},
		{name: "custom KeyGenerator, client with a cookie", cfg: Config{KeyGenerator: pathKey}, blocked: map[string]string{"Cookie": "sid=1"}},
		{
			name:    "custom KeyGenerator, client with a declared header",
			cfg:     Config{KeyGenerator: pathKey, KeyCredentialHeaders: []string{"X-Company-Token"}},
			blocked: map[string]string{"X-Company-Token": "t"},
		},
		{name: "custom KeyGenerator, anonymous client", cfg: Config{KeyGenerator: pathKey}, kept: true},
		{
			name: "custom KeyGenerator, client with a header that is no credential",
			cfg:  Config{KeyGenerator: pathKey}, blocked: map[string]string{"X-Tenant": "acme"}, kept: true,
		},
		// Whoever is refused, a refusal that says not to keep the entry ends it.
		{name: "custom KeyGenerator, anonymous client, refusal says no-store", cfg: Config{KeyGenerator: pathKey}, directive: "no-store"},
	}

	for _, storage := range storageKinds {
		for _, delivery := range []string{"status", "error"} {
			for _, reload := range reloadForms {
				for _, status := range refusalStatuses {
					for _, tc := range tests {
						// A refusal returned as an error is judged by its status alone.
						if tc.directive != "" && delivery == "error" {
							continue
						}
						t.Run(fmt.Sprintf("%s/%s/%s/%d/%s", storage, delivery, reload, status, tc.name), func(t *testing.T) {
							t.Parallel()

							cfg := tc.cfg
							cfg.Storage = storageOf(storage)
							app := fiber.New()
							app.Use(New(cfg))
							app.Get("/", func(c fiber.Ctx) error {
								if c.Get("X-Blocked") != "1" {
									return c.SendString("PUBLIC")
								}
								if tc.directive != "" {
									c.Set(fiber.HeaderCacheControl, tc.directive)
								}
								if delivery == "error" {
									return fiber.NewError(status)
								}
								return c.SendStatus(status)
							})

							require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
							require.Equal(t, cacheHit, getRoot(t, app, nil).cache)

							// A client the app refuses, whatever the key tells of it, reloads.
							headers := map[string]string{"X-Blocked": "1", fiber.HeaderCacheControl: reload}
							maps.Copy(headers, tc.blocked)
							require.Equal(t, status, getRoot(t, app, headers).status)

							want := cacheMiss
							if tc.kept {
								want = cacheHit
							}
							require.Equal(t, want, getRoot(t, app, nil).cache)
						})
					}
				}
			}
		}
	}
}
