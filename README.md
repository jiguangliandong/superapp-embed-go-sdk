# Superapp Embed Go SDK

版本：`v0.0.3`

Partner Backend SDK，负责：

- 服务端生成并一次性保存 `state` 与 PKCE verifier；
- 使用 ES256/RS256 `private_key_jwt` 认证；
- 兑换授权码、刷新、撤销 Token 和读取 UserInfo。

`Client.BaseURL` 必须等于当前环境 User Center 的 Issuer origin（本地默认为
`http://localhost:8081`）。SDK 会请求：

- `{BaseURL}/api/user/v1/open/embed/oauth/token`
- `{BaseURL}/api/user/v1/open/embed/oauth/revoke`
- `{BaseURL}/api/user/v1/open/embed/userinfo`

`private_key_jwt` 的 `aud` 等于完整 Token URL，因此不要把业务网关 origin 和
User Center Issuer 混用。Discovery 在
`{BaseURL}/.well-known/superapp-embed-configuration`，本 SDK 不自动拉取，以免
`aud` 在运行时漂移。

UserInfo 的 `AvatarURL` 是包含不可变文件标识的稳定公共地址。用户更换头像后会返回
新的地址；调用方不需要按临时签名 URL 的过期时间刷新当前地址。

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
