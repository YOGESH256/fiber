package cache

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
)

// What the previous key version left in an external Storage for a request, with the
// credential spelled out in its keys, is deleted when that request misses, so it does not
// wait there to expire. The entries of other credentials are left alone.
func Test_legacyPurge_RemovesWhatThePreviousVersionStoredForTheRequest(t *testing.T) {
	t.Parallel()

	const (
		token = "tok_0123456789abcdefghijklmnopqrstuvwxyz"
		other = "tok_other_other_other_other_other_other"
	)
	storage := newFailingCacheStorage()
	app := fiber.New()
	app.Use(New(Config{Storage: storage, KeyHeaders: []string{"X-API-Key"}}))
	app.Get("/", func(c fiber.Ctx) error {
		c.Set(fiber.HeaderVary, "Accept-Language")
		return c.SendString("body")
	})
	withToken := map[string]string{"X-API-Key": token}
	keys := func() []string {
		storage.mu.RLock()
		defer storage.mu.RUnlock()
		return slices.Collect(maps.Keys(storage.data))
	}

	// The current version keys the request without spelling the credential out.
	require.Equal(t, cacheMiss, getRoot(t, app, withToken).cache)
	var manifest, variant string
	for _, key := range keys() {
		require.NotContains(t, key, token)
		switch {
		case strings.HasSuffix(key, "|vary"):
			manifest = key
		case strings.Contains(key, "|vary|") && !strings.HasSuffix(key, "_body"):
			variant = key
		}
	}
	require.NotEmpty(t, manifest)
	require.NotEmpty(t, variant)
	base := strings.TrimSuffix(manifest, "|vary")
	hashed := "x-api-key:1sha256:" + authDigest(token)
	require.Contains(t, base, hashed)

	// What the previous version stored for it: the same keys under its version, with the
	// credential in the clear. Another credential's entries sit beside them.
	legacy := func(credential string) []string {
		legacyBase := legacyKeyVersion + "|" + strings.TrimPrefix(strings.Replace(base, hashed, "x-api-key:1|"+credential, 1), cacheKeyVersion+"|")
		legacyVariant := legacyBase + strings.TrimPrefix(variant, base)
		return []string{legacyBase, legacyBase + "_body", legacyBase + "|vary", legacyVariant, legacyVariant + "_body"}
	}
	plant := func(credential string) {
		storage.mu.Lock()
		defer storage.mu.Unlock()
		for _, key := range legacy(credential) {
			require.Contains(t, key, credential)
			storage.data[key] = []byte("accept-language")
		}
	}
	present := func(credential string) int {
		storage.mu.RLock()
		defer storage.mu.RUnlock()
		n := 0
		for _, key := range legacy(credential) {
			if _, ok := storage.data[key]; ok {
				n++
			}
		}
		return n
	}
	forgetCurrent := func() {
		storage.mu.Lock()
		defer storage.mu.Unlock()
		maps.DeleteFunc(storage.data, func(key string, _ []byte) bool {
			return strings.HasPrefix(key, cacheKeyVersion+"|")
		})
	}
	plant(token)
	plant(other)
	forgetCurrent()

	// A request without the credential is not the one those entries were stored for.
	require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
	require.Equal(t, 5, present(token))
	forgetCurrent()

	// The one that sends it ends them, and stores its answer under the current version.
	require.Equal(t, cacheMiss, getRoot(t, app, withToken).cache)
	require.Zero(t, present(token), "the credential is still spelled out in a key")
	require.Equal(t, 5, present(other), "another credential's entries went with it")
	for _, key := range keys() {
		if strings.HasPrefix(key, cacheKeyVersion+"|") {
			require.NotContains(t, key, token)
		}
	}
	require.Equal(t, cacheHit, getRoot(t, app, withToken).cache)
}

// The purge adds a bounded amount of work, and only where a previous version can have
// left something: an external Storage, and a credential header the default key hashes.
func Test_legacyPurge_IsBoundedAndOnlyWhereItCanMatter(t *testing.T) {
	t.Parallel()

	t.Run("not for memory, a custom key or no credential header", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		for name, cfg := range map[string]Config{
			"memory":     {KeyHeaders: []string{"X-API-Key"}},
			"custom key": {Storage: storage, KeyHeaders: []string{"X-API-Key"}, KeyGenerator: pathKey},
			"none":       {Storage: storage},
		} {
			cfg = configDefault(cfg)
			require.Nil(t, newLegacyPurge(&cfg, nil), name)
		}
	})

	t.Run("past its budget it leaves entries to expire", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{Storage: storage, KeyHeaders: []string{"X-API-Key"}})
		purge := newLegacyPurge(&cfg, newManager(storage, true))
		require.NotNil(t, purge)

		c := requestWith(map[string]string{"X-API-Key": "tok"})
		legacyBase := legacyKeyVersion + "|GET|" + string(appendDefaultKey(nil, c, &purge.cfg))
		require.Contains(t, legacyBase, "x-api-key:1|tok")
		storage.data[legacyBase] = []byte("entry")

		purge.probes.Store(maxLegacyProbes)
		purge.purge(c, false)
		require.Contains(t, storage.data, legacyBase)

		purge.probes.Store(maxLegacyProbes - 1)
		purge.purge(c, false)
		require.NotContains(t, storage.data, legacyBase)
		require.Equal(t, int64(maxLegacyProbes), purge.probes.Load())
	})
}
