# Superapp Embed Go SDK

Partner Backend SDK，负责：

- 服务端生成并一次性保存 `state` 与 PKCE verifier；
- 使用 ES256/RS256 `private_key_jwt` 认证；
- 兑换授权码、刷新、撤销 Token 和读取 UserInfo。

UserInfo 的 `AvatarURL` 和 `AvatarURLExpiresAt` 保留用于兼容已有 V1 接入；新接入应使用
稳定公共地址 `AvatarPublicURL`。用户更换头像后，后续 UserInfo 会返回新的公共地址。

`MemoryTransactionStore` 只用于 Demo/测试；多实例生产服务使用
`RedisTransactionStore`。Redis 实现会使用 AES-256-GCM 加密完整交易，并保证
`Take` 是跨实例的原子读取后删除。

```go
store := embedsdk.NewMemoryTransactionStore()
transactions := embedsdk.NewTransactionManager(clientID, store, 5*time.Minute)
bootstrap, _ := transactions.Begin(
    ctx, partnerBrowserSessionID, []string{"auth_base", "profile.name"},
)

transaction, _ := transactions.Complete(
    ctx, transactionID, returnedState, partnerBrowserSessionID,
)
token, _ := client.ExchangeAuthorizationCode(ctx, code, transaction.CodeVerifier)
```

生产环境示例：

```go
redisClient := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_ADDR"),
})

// 必须从 Secret Manager/KMS 读取 32 字节随机密钥，不能硬编码。
encryptionKey, err := base64.RawURLEncoding.DecodeString(
    os.Getenv("SUPERAPP_EMBED_TRANSACTION_KEY"),
)
if err != nil {
    log.Fatal(err)
}
store, err := embedsdk.NewRedisTransactionStore(
    redisClient,
    encryptionKey,
    embedsdk.WithRedisTransactionKeyPrefix("partner:embed:transaction:"),
)
if err != nil {
    log.Fatal(err)
}
transactions := embedsdk.NewTransactionManager(clientID, store, 5*time.Minute)
```

运行：

```bash
go test ./...
```
