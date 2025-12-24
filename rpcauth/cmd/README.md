# 生成手順

以下のコマンドで認証に必要なデータを生成します。

```bash
go run ./rpcauth/cmd/generator.go -username <User Name>
```

以下が実行例です。

```bash
> go run ./rpcauth/cmd/generator.go -username alice
╔════════════════════════════════════════════════════════════════╗
║          PeerSwap RPC Authentication Credentials               ║
╚════════════════════════════════════════════════════════════════╝

📝 Configuration File Entry
───────────────────────────────────────────────────────────────
Add this line to your peerswap.conf:

  rpcauth=alice:729ec784c089d9fc6478b6cf2d01070a$be97e2b6b39fc9ccfb90e0aa67085b79da4c5399cdc69579675570b1b40578fb

🔐 Your Credentials
───────────────────────────────────────────────────────────────
  Username: alice
  Password: NCrX9XKJQ23MNk9EOyRL4V9A0rqyN52b
```
