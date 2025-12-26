# 生成手順

以下のコマンドで認証に必要なデータを生成します。

```bash
go run ./rpcauth/cmd/generator.go -username <User Name>
```

`--password`を指定することで任意のパスワードを設定することができます。</br>
指定がない場合にはランダム値が設定されます。

```bash
NAME:
   ps-rpcauth-generator - Generate rpcauth credentials for PeerSwap gRPC authentication

USAGE:
    [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --username value  Username for authentication (required)
   --password value  Password (leave empty to auto-generate)
   --help, -h        show help
```

以下が実行例です。

```bash
> go run rpcauth/cmd/generator.go --username alice
╔════════════════════════════════════════════════════════════════╗
║          PeerSwap RPC Authentication Credentials               ║
╚════════════════════════════════════════════════════════════════╝

📝 Configuration File Entry
───────────────────────────────────────────────────────────────
Add this line to your peerswap.conf:

  rpcauth=alice:7e9d0ed053fd4c3ef3bb053ef9b5fdd5$160c5b02306136e66e388f569799d7ce97a09fbe021f215787a137c223143542

🔐 Your Credentials
───────────────────────────────────────────────────────────────
  Username: alice
  Password: QQ8ldomXkv9Y5nVDLVxoapn1_a333scK

🧾 Encoded Basic Auth (Base64 of username:password)
───────────────────────────────────────────────────────────────
  YWxpY2U6UVE4bGRvbVhrdjlZNW5WRExWeG9hcG4xX2EzMzNzY0s=

Use in HTTP header as: Authorization: Basic YWxpY2U6UVE4bGRvbVhrdjlZNW5WRExWeG9hcG4xX2EzMzNzY0s=
```
