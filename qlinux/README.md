# Project QLinux

量子セキュア通信を目指した実験的OSカーネル + 暗号ライブラリ群。

## クレート構成

| クレート | 概要 |
|---|---|
| `qhal` | 量子ハードウェア抽象化レイヤー (ThermalRNG) |
| `key_pool` | OTP鍵プール管理 |
| `otp_engine` | OTP暗号化/復号エンジン |
| `auth` | 3要素認証 (Bio + Password + TPM2.0) |
| `uhf` | ユニバーサルハッシュ関数 (Poly1305 / GHASH / UMAC-64) |
| `wc_auth` | WC認証セッション (word_count nonce方式) |
| `kernel/` | no_std カーネルモジュール群 |

## セキュリティ設計

- 全鍵材料は `Zeroize` でメモリ消去
- タグ比較は定数時間 (`ct_eq_16`)
- Poly1305: RFC 8439 準拠、26bit limb 実装
- WC認証: word_count 単調増加によるリプレイ攻撃対策

## ライセンス

MIT

#### MEDIUM (3件)
| # | 場所 | 脆弱性 | 修正 |
|---|------|--------|------|
| 14 | key_pool | low_water_mark=0設定可能 | MIN_LOW_WATER_MARK(64)未満は拒否 |
| 15 | key_pool | 空Vecの鍵を追加可能 | EmptyKeyMaterialエラーで拒否 |
| 16 | key_pool | available_bytes()とacquire()のTOCTOU | 単一Mutexで原子的に操作 |
