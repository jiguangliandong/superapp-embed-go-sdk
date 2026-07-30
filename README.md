# Supperapp Embed Go SDK

Partner Backend SDK，负责：

- 服务端生成并一次性保存 `state` 与 PKCE verifier；
- 使用 ES256/RS256 `private_key_jwt` 认证；
- 兑换授权码、刷新、撤销 Token 和读取 UserInfo。

`MemoryTransactionStore` 只用于 Demo/测试；多实例生产服务应实现
`TransactionStore` 并使用 Redis 的原子取出语义。

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

运行：

```bash
go test ./...
```
