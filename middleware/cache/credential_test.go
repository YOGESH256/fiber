package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/utils/v2"
	"github.com/stretchr/testify/require"
)

func Test_carriesCredential(t *testing.T) {
	t.Parallel()

	cfg := configDefault(Config{KeyCredentialHeaders: []string{"X-Company-Token"}})
	for name, want := range map[string]bool{
		"Authorization":       true,
		"authorization":       true,
		"COOKIE":              true,
		"Proxy-Authorization": true,
		"X-API-Key":           true,
		"x-auth-token":        true,
		"X-Access-Token":      true,
		"X-Company-Token":     true,
		"x-company-token":     true,
		"X-Tenant":            false,
		"Accept-Language":     false,
		"Set-Cookie":          false,
		"X-Authorization":     false,
		"":                    false,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, want, cfg.carriesCredential(name))
		})
	}
}

// pathKey is the smallest custom KeyGenerator: whatever the request carries, the key is its path.
func pathKey(c fiber.Ctx) string { return c.Path() }

// requestWith returns the context of a request that carries the headers.
func requestWith(headers map[string]string) fiber.Ctx {
	c, _ := buildKeygenCtx(&keygenCase{uri: "/", headers: headers})
	return c
}

func Test_scopeOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		headers          map[string]string
		name             string
		cfg              Config
		hasAuthorization bool
		wantEntry        bool
		wantKeyed        bool
	}{
		// The default key is built from the request, so a refusal reaches the entry it found.
		{name: "nothing in the key", wantEntry: true},
		{name: "Authorization", hasAuthorization: true, wantEntry: true, wantKeyed: true},
		{
			name: "KeyCookies cookie present", cfg: Config{KeyCookies: []string{"session"}},
			headers: map[string]string{"Cookie": "session=abc"}, wantEntry: true, wantKeyed: true,
		},
		{name: "KeyCookies cookie absent", cfg: Config{KeyCookies: []string{"session"}}, wantEntry: true},
		{
			name: "recognized header in KeyHeaders present", cfg: Config{KeyHeaders: []string{"X-API-Key"}},
			headers: map[string]string{"X-API-Key": "k"}, wantEntry: true, wantKeyed: true,
		},
		{name: "recognized header in KeyHeaders absent", cfg: Config{KeyHeaders: []string{"X-API-Key"}}, wantEntry: true},
		{
			name: "header in KeyHeaders that is not a credential", cfg: Config{KeyHeaders: []string{"X-Tenant"}},
			headers: map[string]string{"X-Tenant": "acme"}, wantEntry: true,
		},
		{
			name: "declared header present", cfg: Config{KeyCredentialHeaders: []string{"X-Company-Token"}},
			headers: map[string]string{"X-Company-Token": "t"}, wantEntry: true, wantKeyed: true,
		},
		// A custom KeyGenerator's key is opaque: the refusal has to be a verdict on a
		// credential the key may hold, and Authorization is in every key.
		{
			name: "custom KeyGenerator, request with a cookie", cfg: Config{KeyGenerator: pathKey},
			headers: map[string]string{"Cookie": "sid=1"}, wantEntry: true,
		},
		{
			name:    "custom KeyGenerator, request with a declared header",
			cfg:     Config{KeyGenerator: pathKey, KeyCredentialHeaders: []string{"X-Company-Token"}},
			headers: map[string]string{"X-Company-Token": "t"}, wantEntry: true,
		},
		{name: "custom KeyGenerator, Authorization", cfg: Config{KeyGenerator: pathKey}, hasAuthorization: true, wantEntry: true, wantKeyed: true},
		// Nothing the key could hold: a client that sends no credential and is turned away
		// for its own reasons must not end the entry the others share.
		{name: "custom KeyGenerator, anonymous request", cfg: Config{KeyGenerator: pathKey}},
		{
			name: "custom KeyGenerator, request with a header that is not a credential", cfg: Config{KeyGenerator: pathKey},
			headers: map[string]string{"X-Tenant": "acme"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := configDefault(tc.cfg)
			scope := cfg.scopeOf(requestWith(tc.headers), tc.hasAuthorization)
			require.Equal(t, tc.wantEntry, scope.entry, "entry")
			require.Equal(t, tc.wantKeyed, scope.keyed, "keyed")
		})
	}
}

func Test_keyLog(t *testing.T) {
	t.Parallel()

	t.Run("forgets the oldest past its limit", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{limit: 2}
		require.Empty(t, l.add("a"))
		require.Empty(t, l.add("b"))
		require.Equal(t, "a", l.add("c"))
		require.Equal(t, "b", l.add("d"))
	})

	t.Run("a key seen again is the newest", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{limit: 2}
		l.add("a")
		l.add("b")
		require.Empty(t, l.add("a"))
		require.Equal(t, "b", l.add("c"))
	})

	t.Run("a removed key leaves room", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{limit: 2}
		l.add("a")
		l.add("b")
		l.remove("a")
		l.remove("never seen")
		require.Empty(t, l.add("c"))
		require.Equal(t, "b", l.add("d"))
	})

	t.Run("no limit forgets nothing, so keeps nothing", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{}
		for i := range 100 {
			require.Empty(t, l.add(strconv.Itoa(i)))
		}
		require.Empty(t, l.items)
	})
}

func Test_refusalLimit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cfg  Config
		want int
	}{
		{name: "sized by MaxBytes", cfg: Config{MaxBytes: 1 << 20}, want: 4096},
		{name: "never fewer than the minimum", cfg: Config{MaxBytes: 1}, want: minRefusalRecords},
		{name: "no limit as for MaxBytes", cfg: Config{}},
		{name: "overridden", cfg: Config{MaxBytes: 1 << 20, refusalRecordLimit: 7}, want: 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, tc.cfg.refusalLimit())
		})
	}
}

// A hit has a record to find only where one can exist: in a Storage anything may have
// written one, in the private in-memory store only this middleware, until the last has expired.
func Test_refusalRecords_mayHold(t *testing.T) {
	t.Parallel()

	t.Run("in memory, from the first record until the last has expired", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{})
		records := newRefusalRecords(&cfg, newManager(nil, true))
		require.False(t, records.mayHold())

		records.record(context.Background(), "base|refused|vary|digest", 0)
		require.True(t, records.mayHold())

		// The store drops its records at its own clock, which is the one read here.
		records.until.Store(uint64(utils.Timestamp()))
		require.False(t, records.mayHold())
	})

	t.Run("a record is kept for Expiration, or as long as the refused entry had left", func(t *testing.T) {
		t.Parallel()

		now := time.Unix(1_700_000_000, 0)
		cfg := configDefault(Config{Expiration: time.Minute, clock: func() time.Time { return now }})
		kept := func(entryExp uint64) uint64 {
			records := newRefusalRecords(&cfg, newManager(nil, true))
			before := uint64(utils.Timestamp())
			records.record(context.Background(), "base|refused|vary|digest", entryExp)
			return records.until.Load() - before
		}
		// Whole seconds, plus the two the gate adds to cover the store's rounding and a tick.
		within := func(got, seconds uint64) {
			t.Helper()
			require.GreaterOrEqual(t, got, seconds+2)
			require.LessOrEqual(t, got, seconds+6)
		}

		within(kept(0), 60)
		within(kept(uint64(now.Unix())+10), 60)
		within(kept(uint64(now.Unix())+3600), 3600)
	})

	t.Run("in a Storage, always", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{Storage: newFailingCacheStorage()})
		require.True(t, newRefusalRecords(&cfg, newManager(cfg.Storage, true)).mayHold())
	})
}

func Test_refusesCredential(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status int
		want   bool
	}{
		{status: fiber.StatusUnauthorized, want: true},
		{status: fiber.StatusForbidden, want: true},
		{status: fiber.StatusProxyAuthRequired, want: true},
		{status: fiber.StatusOK},
		{status: fiber.StatusFound},
		{status: fiber.StatusNotFound},
		{status: fiber.StatusTooManyRequests},
		{status: fiber.StatusServiceUnavailable},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, refusesCredential(tc.status))
		})
	}
}

func Test_errorRefusesCredential(t *testing.T) {
	t.Parallel()

	// A nil *fiber.Error held in an error matches errors.As, and must not be read.
	var typedNil *fiber.Error

	for _, tc := range []struct {
		err  error
		name string
		want bool
	}{
		{name: "nil"},
		{name: "401", err: fiber.ErrUnauthorized, want: true},
		{name: "403", err: fiber.ErrForbidden, want: true},
		{name: "407", err: fiber.ErrProxyAuthRequired, want: true},
		{name: "custom message", err: fiber.NewError(fiber.StatusForbidden, "tenant suspended"), want: true},
		{name: "wrapped", err: fmt.Errorf("session: %w", fiber.ErrUnauthorized), want: true},
		{name: "joined", err: errors.Join(errors.New("audit failed"), fiber.ErrForbidden), want: true},
		{name: "503", err: fiber.ErrServiceUnavailable},
		{name: "404", err: fiber.ErrNotFound},
		{name: "not a fiber error", err: errors.New("unauthorized")},
		{name: "typed nil", err: typedNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, errorRefusesCredential(tc.err))
		})
	}
}

func Test_varyListsCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		vary     string
		declared []string
		want     bool
	}{
		{vary: "", want: false},
		{vary: "Accept", want: false},
		{vary: "Accept-Encoding, Accept-Language", want: false},
		{vary: "*", want: false},
		{vary: "Cookie", want: true},
		{vary: "cookie", want: true},
		{vary: "COOKIE", want: true},
		{vary: " Cookie ", want: true},
		{vary: "Accept-Encoding, Cookie", want: true},
		{vary: "Accept-Encoding,Cookie", want: true},
		{vary: "Authorization", want: true},
		{vary: "authorization", want: true},
		// The other headers that carry nothing but a credential.
		{vary: "Proxy-Authorization", want: true},
		{vary: "X-API-Key", want: true},
		{vary: "Accept, x-auth-token", want: true},
		{vary: "X-Access-Token", want: true},
		// Names that merely contain one of them are other fields.
		{vary: "X-Cookie", want: false},
		{vary: "Cookie2", want: false},
		{vary: "Set-Cookie", want: false},
		{vary: "X-Authorization", want: false},
		// A header is a credential only when it is declared.
		{vary: "X-Company-Token", want: false},
		{vary: "X-Company-Token", declared: []string{"x-company-token"}, want: true},
		{vary: "Accept, X-COMPANY-TOKEN", declared: []string{"x-company-token"}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.vary, func(t *testing.T) {
			t.Parallel()
			cfg := Config{KeyCredentialHeaders: tc.declared}
			require.Equal(t, tc.want, cfg.varyListsCredential([]byte(tc.vary)), "Vary: %q", tc.vary)
		})
	}
}

func Test_refusalKey(t *testing.T) {
	t.Parallel()

	cfg := configDefault(Config{KeyCredentialHeaders: []string{"X-Company-Token"}})
	key := func(base string, vary []string, headers map[string]string) string {
		return cfg.refusalKey(requestWith(headers), base, vary, false)
	}
	session := map[string]string{"Cookie": "session=abc"}

	t.Run("there is nothing to record unless a credential is sent that the responses vary on", func(t *testing.T) {
		t.Parallel()

		require.Empty(t, key("base", nil, session), "no Vary")
		require.Empty(t, key("base", []string{"x-tenant"}, session), "a Vary on no credential")
		require.Empty(t, key("base", []string{"cookie"}, nil), "no credential sent")
		require.Empty(t, key("base", []string{"x-api-key"}, session), "another credential sent")
		require.Empty(t, key("base", []string{"cookie"}, map[string]string{"X-Company-Token": "t"}))
		require.Empty(t, cfg.refusalKey(requestWith(session), "base", []string{"cookie"}, true), "the key holds Authorization")
	})

	t.Run("one record reaches every variant of the credential and none of another", func(t *testing.T) {
		t.Parallel()

		got := key("base", []string{"cookie", "x-variant"}, session)
		require.NotEmpty(t, got)
		require.Equal(t, got, key("base", []string{"cookie"}, session), "the other Vary names are not part of the record")
		require.Equal(t, got, key("base", []string{"cookie", "x-variant"}, map[string]string{"Cookie": "session=abc", "X-Variant": "two"}))
		require.NotEqual(t, got, key("base", []string{"cookie"}, map[string]string{"Cookie": "session=other"}))
		require.NotEqual(t, got, key("other", []string{"cookie"}, session))
		require.True(t, strings.HasPrefix(got, "base|refused|"), "%q", got)
	})

	t.Run("a declared header is a credential, held by the key or not", func(t *testing.T) {
		t.Parallel()

		token := map[string]string{"X-Company-Token": "t"}
		record := func(cfg Config, vary []string, headers map[string]string) string {
			cfg = configDefault(cfg)
			return cfg.refusalKey(requestWith(headers), "base", vary, false)
		}
		varyToken := []string{"x-company-token"}
		declared := Config{KeyCredentialHeaders: []string{"X-Company-Token"}}
		custom := Config{KeyCredentialHeaders: []string{"X-Company-Token"}, KeyGenerator: pathKey}

		// The default key is built from it, so the manifest is the credential's own.
		require.Empty(t, record(declared, varyToken, token))

		// A custom key ignores it, so the manifest is shared and the refusal gets a record,
		// whatever the responses vary on.
		got := record(custom, varyToken, token)
		require.NotEmpty(t, got)
		require.NotEqual(t, got, record(custom, varyToken, map[string]string{"X-Company-Token": "u"}))
		require.Empty(t, record(custom, varyToken, nil))
		require.NotEmpty(t, record(custom, nil, token))
	})
}
