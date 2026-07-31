package embedsdk

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrTransactionNotFound = errors.New("embed SSO transaction not found or expired")
	ErrStateMismatch       = errors.New("embed SSO state mismatch")
)

// Transaction 保存 Partner Backend 专属的短期 PKCE 和 state 状态。
type Transaction struct {
	ID           string
	State        string
	CodeVerifier string
	Binding      string
	Scopes       []string
	ExpiresAt    time.Time
}

// Bootstrap 是可以安全返回给 H5 的事务公开部分。
type Bootstrap struct {
	TransactionID string   `json:"transaction_id"`
	ClientID      string   `json:"client_id"`
	State         string   `json:"state"`
	CodeChallenge string   `json:"code_challenge"`
	Scopes        []string `json:"scopes"`
}

// TransactionStore 必须以一次性语义保存和取出事务。
type TransactionStore interface {
	Put(context.Context, Transaction) error
	Take(context.Context, string) (Transaction, error)
}

// TransactionManager 在 Partner Backend 生成 PKCE verifier，使其永不进入 H5。
type TransactionManager struct {
	clientID string
	store    TransactionStore
	ttl      time.Duration
	now      func() time.Time
}

func NewTransactionManager(clientID string, store TransactionStore, ttl time.Duration) *TransactionManager {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &TransactionManager{clientID: clientID, store: store, ttl: ttl, now: time.Now}
}

func (manager *TransactionManager) Begin(
	ctx context.Context,
	binding string,
	scopes []string,
) (Bootstrap, error) {
	id, err := randomValue(24)
	if err != nil {
		return Bootstrap{}, err
	}
	state, err := randomValue(32)
	if err != nil {
		return Bootstrap{}, err
	}
	verifier, err := randomValue(64)
	if err != nil {
		return Bootstrap{}, err
	}
	if len(scopes) == 0 {
		scopes = []string{"auth_base"}
	}
	transaction := Transaction{
		ID: id, State: state, CodeVerifier: verifier, Binding: binding,
		Scopes: append([]string(nil), scopes...), ExpiresAt: manager.now().UTC().Add(manager.ttl),
	}
	if err := manager.store.Put(ctx, transaction); err != nil {
		return Bootstrap{}, err
	}
	digest := sha256.Sum256([]byte(verifier))
	return Bootstrap{
		TransactionID: id, ClientID: manager.clientID, State: state,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
		Scopes:        append([]string(nil), scopes...),
	}, nil
}

// Complete 原子消费事务并校验 state。即使 state 错误也不允许重试同一事务。
func (manager *TransactionManager) Complete(
	ctx context.Context,
	transactionID, returnedState, binding string,
) (Transaction, error) {
	transaction, err := manager.store.Take(ctx, transactionID)
	if err != nil || !transaction.ExpiresAt.After(manager.now().UTC()) {
		return Transaction{}, ErrTransactionNotFound
	}
	if subtle.ConstantTimeCompare([]byte(transaction.State), []byte(returnedState)) != 1 {
		return Transaction{}, ErrStateMismatch
	}
	if subtle.ConstantTimeCompare([]byte(transaction.Binding), []byte(binding)) != 1 {
		return Transaction{}, ErrTransactionNotFound
	}
	return transaction, nil
}

// MemoryTransactionStore 只适用于单进程 Demo 和测试；多实例环境应使用共享原子存储。
type MemoryTransactionStore struct {
	mu    sync.Mutex
	items map[string]Transaction
}

func NewMemoryTransactionStore() *MemoryTransactionStore {
	return &MemoryTransactionStore{items: make(map[string]Transaction)}
}

func (store *MemoryTransactionStore) Put(_ context.Context, transaction Transaction) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.items[transaction.ID] = transaction
	return nil
}

func (store *MemoryTransactionStore) Take(_ context.Context, id string) (Transaction, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	transaction, ok := store.items[id]
	delete(store.items, id)
	if !ok {
		return Transaction{}, ErrTransactionNotFound
	}
	return transaction, nil
}

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
