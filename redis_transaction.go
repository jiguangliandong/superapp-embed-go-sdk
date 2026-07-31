package embedsdk

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultRedisTransactionKeyPrefix = "superapp:embed:sso:transaction:"
	redisTransactionPayloadVersion   = byte(1)
)

var (
	// ErrInvalidRedisEncryptionKey 表示 Redis 交易加密密钥不是 32 字节。
	ErrInvalidRedisEncryptionKey = errors.New("embed SSO Redis encryption key must be 32 bytes")
	// ErrTransactionExpired 表示调用 Put 时交易已经过期。
	ErrTransactionExpired = errors.New("embed SSO transaction is already expired")
)

// RedisTransactionClient 是 RedisTransactionStore 所需的最小 Redis 客户端能力。
// *redis.Client、*redis.ClusterClient 和 redis.UniversalClient 均满足该接口。
type RedisTransactionClient interface {
	Set(context.Context, string, interface{}, time.Duration) *redis.StatusCmd
	Eval(context.Context, string, []string, ...interface{}) *redis.Cmd
}

// RedisTransactionStoreOption 配置 RedisTransactionStore。
type RedisTransactionStoreOption func(*redisTransactionStoreOptions)

type redisTransactionStoreOptions struct {
	keyPrefix string
	now       func() time.Time
}

// WithRedisTransactionKeyPrefix 设置 Redis Key 前缀。
//
// 不同环境或不同 Client 共用 Redis 时应使用不同前缀，避免命名冲突。前缀为空时使用
// "superapp:embed:sso:transaction:"。
func WithRedisTransactionKeyPrefix(prefix string) RedisTransactionStoreOption {
	return func(options *redisTransactionStoreOptions) {
		if prefix != "" {
			options.keyPrefix = prefix
		}
	}
}

// RedisTransactionStore 使用 Redis 跨实例保存一次性登录交易。
//
// 交易整体使用 AES-256-GCM 加密，避免 PKCE Verifier、State 和 Session Binding
// 以明文进入 Redis。Take 通过一段 Lua 脚本原子读取并删除交易；即使后续校验失败，
// 同一交易也不能再次使用。
type RedisTransactionStore struct {
	client    RedisTransactionClient
	keyPrefix string
	aead      cipher.AEAD
	now       func() time.Time
}

var _ TransactionStore = (*RedisTransactionStore)(nil)

// NewRedisTransactionStore 创建生产可用的 Redis 登录交易存储。
//
// encryptionKey 必须是来自 Secret Manager、KMS 或等价密钥管理系统的 32 字节随机值；
// 不能使用 Client ID、密码或其他可猜测文本派生。更新密钥会使尚未消费的旧交易失效，
// 因此轮换时应至少保留一个交易 TTL 的兼容窗口，或接受用户重新发起登录。
func NewRedisTransactionStore(
	client RedisTransactionClient,
	encryptionKey []byte,
	options ...RedisTransactionStoreOption,
) (*RedisTransactionStore, error) {
	if client == nil {
		return nil, errors.New("embed SSO Redis client is required")
	}
	if len(encryptionKey) != 32 {
		return nil, ErrInvalidRedisEncryptionKey
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create embed SSO Redis cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create embed SSO Redis AEAD: %w", err)
	}
	config := redisTransactionStoreOptions{
		keyPrefix: defaultRedisTransactionKeyPrefix,
		now:       time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}
	return &RedisTransactionStore{
		client: client, keyPrefix: config.keyPrefix, aead: aead, now: config.now,
	}, nil
}

func (store *RedisTransactionStore) Put(ctx context.Context, transaction Transaction) error {
	now := store.now().UTC()
	ttl := transaction.ExpiresAt.Sub(now)
	if ttl <= 0 {
		return ErrTransactionExpired
	}
	key := store.key(transaction.ID)
	payload, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("marshal embed SSO transaction: %w", err)
	}
	nonce := make([]byte, store.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate embed SSO Redis nonce: %w", err)
	}
	sealed := store.aead.Seal(nil, nonce, payload, []byte(key))
	value := make([]byte, 1+len(nonce)+len(sealed))
	value[0] = redisTransactionPayloadVersion
	copy(value[1:], nonce)
	copy(value[1+len(nonce):], sealed)
	if err := store.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("store embed SSO transaction in Redis: %w", err)
	}
	return nil
}

func (store *RedisTransactionStore) Take(ctx context.Context, id string) (Transaction, error) {
	key := store.key(id)
	result, err := store.client.Eval(ctx, redisTakeTransactionScript, []string{key}).Text()
	if errors.Is(err, redis.Nil) {
		return Transaction{}, ErrTransactionNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("take embed SSO transaction from Redis: %w", err)
	}
	transaction, err := store.open(key, []byte(result))
	if err != nil {
		return Transaction{}, err
	}
	return transaction, nil
}

func (store *RedisTransactionStore) open(key string, value []byte) (Transaction, error) {
	minimumLength := 1 + store.aead.NonceSize() + store.aead.Overhead()
	if len(value) < minimumLength || value[0] != redisTransactionPayloadVersion {
		return Transaction{}, errors.New("invalid embed SSO Redis transaction payload")
	}
	nonceEnd := 1 + store.aead.NonceSize()
	plaintext, err := store.aead.Open(
		nil,
		value[1:nonceEnd],
		value[nonceEnd:],
		[]byte(key),
	)
	if err != nil {
		return Transaction{}, errors.New("invalid embed SSO Redis transaction payload")
	}
	var transaction Transaction
	if err := json.Unmarshal(plaintext, &transaction); err != nil {
		return Transaction{}, errors.New("invalid embed SSO Redis transaction payload")
	}
	return transaction, nil
}

func (store *RedisTransactionStore) key(id string) string {
	return store.keyPrefix + strings.TrimSpace(id)
}

const redisTakeTransactionScript = `
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
end
return value
`
