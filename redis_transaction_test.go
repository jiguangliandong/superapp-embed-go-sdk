package embedsdk

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisTransactionStoreEncryptsAndAtomicallyTakesTransaction(t *testing.T) {
	redisServer := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() {
		_ = redisClient.Close()
	})

	keyPrefix := "test:embed:transaction:"
	store, err := NewRedisTransactionStore(
		redisClient,
		bytes.Repeat([]byte{0x42}, 32),
		WithRedisTransactionKeyPrefix(keyPrefix),
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction := Transaction{
		ID:           "transaction-1",
		State:        "sensitive-state",
		CodeVerifier: "sensitive-pkce-verifier",
		Binding:      "sensitive-browser-session",
		Scopes:       []string{"auth_base", "profile.name"},
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
	}
	if err := store.Put(context.Background(), transaction); err != nil {
		t.Fatal(err)
	}

	rawValue, err := redisClient.Get(
		context.Background(),
		keyPrefix+transaction.ID,
	).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{transaction.State, transaction.CodeVerifier, transaction.Binding} {
		if bytes.Contains(rawValue, []byte(secret)) {
			t.Fatalf("Redis payload leaked %q", secret)
		}
	}

	taken, err := store.Take(context.Background(), transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if taken.ID != transaction.ID ||
		taken.State != transaction.State ||
		taken.CodeVerifier != transaction.CodeVerifier ||
		taken.Binding != transaction.Binding ||
		!taken.ExpiresAt.Equal(transaction.ExpiresAt) {
		t.Fatalf("taken transaction = %#v, want %#v", taken, transaction)
	}
	if _, err := store.Take(context.Background(), transaction.ID); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("second Take error = %v, want ErrTransactionNotFound", err)
	}
}

func TestRedisTransactionStoreAllowsOnlyOneConcurrentTake(t *testing.T) {
	redisServer := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() {
		_ = redisClient.Close()
	})
	store, err := NewRedisTransactionStore(redisClient, bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transaction := Transaction{
		ID: "transaction-concurrent", ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	if err := store.Put(context.Background(), transaction); err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	var successes atomic.Int32
	var unexpected atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for range attempts {
		go func() {
			defer waitGroup.Done()
			_, takeErr := store.Take(context.Background(), transaction.ID)
			switch {
			case takeErr == nil:
				successes.Add(1)
			case errors.Is(takeErr, ErrTransactionNotFound):
			default:
				unexpected.Add(1)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 || unexpected.Load() != 0 {
		t.Fatalf(
			"concurrent Take successes = %d, unexpected errors = %d",
			successes.Load(),
			unexpected.Load(),
		)
	}
}

func TestRedisTransactionStoreExpiresTransaction(t *testing.T) {
	redisServer := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() {
		_ = redisClient.Close()
	})
	store, err := NewRedisTransactionStore(redisClient, bytes.Repeat([]byte{0x18}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transaction := Transaction{
		ID: "transaction-expiring", ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	if err := store.Put(context.Background(), transaction); err != nil {
		t.Fatal(err)
	}
	redisServer.FastForward(2 * time.Minute)

	if _, err := store.Take(context.Background(), transaction.ID); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("Take error = %v, want ErrTransactionNotFound", err)
	}
}

func TestNewRedisTransactionStoreRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewRedisTransactionStore(nil, make([]byte, 32)); err == nil {
		t.Fatal("nil Redis client should be rejected")
	}
	redisServer := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() {
		_ = redisClient.Close()
	})
	if _, err := NewRedisTransactionStore(redisClient, []byte("too-short")); !errors.Is(
		err,
		ErrInvalidRedisEncryptionKey,
	) {
		t.Fatalf("invalid key error = %v, want ErrInvalidRedisEncryptionKey", err)
	}

	store, err := NewRedisTransactionStore(redisClient, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), Transaction{
		ID: "expired", ExpiresAt: time.Now().UTC().Add(-time.Second),
	}); !errors.Is(err, ErrTransactionExpired) {
		t.Fatalf("expired Put error = %v, want ErrTransactionExpired", err)
	}
}
