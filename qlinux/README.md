# QLinux - 量子OTP暗号化OS

## プロジェクト構造

```
qlinux/
├── qhal/            # Quantum Hardware Abstraction Layer (Week1)
│   └── src/drivers/ # ThermalRNG | Phase2: QKD_Fiber/QKD_Repeater | Phase3: Teleportation
├── key_pool/        # Key Pool Manager - 3ステート + ゼロ埋め (Week2)
├── otp_engine/      # OTP暗号化エンジン + 鍵破棄 (Week3)
├── auth/            # 認証レイヤー Bio + PW + TPM2.0
├── kernel_module/   # netfilter + XFRM カーネルモジュール (C)
└── tools/           # CLIツール (entropy-check, pool-status)
```

## ロードマップ

| フェーズ | 期日 | 内容 |
|---------|------|------|
| Week1 | 2026/04/27 | QHAL trait + ThermalRNG /dev/hwrng + dieharder検証 |
| Week2 | 2026/05/04 | Key Pool Manager 3ステート + ゼロ埋め + 通信停止ロジック |
| Week3 | 2026/05/11 | OTP暗号化エンジン + 鍵消費・破棄フロー |
| Week4 | 2026/05/18 | 2ノード間通信テスト (閉域LAN) |
| Phase2 | - | QKD_Fiber/QKD_Repeater ドライバ (ETSI GS QKD 014) |
| Phase3 | - | Teleportationチャンネル対応 |

## ビルド

```bash
cargo build --workspace
```

## セキュリティ設計原則

- OTPの再利用は構造上不可能（Consumed状態でゼロ埋め）
- 鍵長 ≥ 平文長を実行時保証
- 3要素認証（生体 + PW + TPM2.0）なしに鍵アクセス不可
- プール残量が低水位線以下で通信自動停止
- ローカル処理のみ（生体テンプレート外部送信なし）
- PFS非採用の設計根拠を脅威モデル文書に明文化

## セキュリティリファクタリング履歴

### 発見された脆弱性と修正 (16件)

#### CRITICAL (8件)
| # | 場所 | 脆弱性 | 修正 |
|---|------|--------|------|
| 1 | key_pool | acquire後panicで鍵がInUseのまま残留 | ブロック全体をmoveし残留バイトなし |
| 2 | key_pool | consume後もdataがVecに残りゼロ化未実施 | consume時にVecから削除→dropでゼロ化 |
| 3 | key_pool | 2つのMutexによるTOCTOU・デッドロック | next_idをpoolと同一Mutexに統合 |
| 4 | key_pool | Mutex毒化で全操作が永久失敗 | LockPoisonedエラーを明示的に返却 |
| 5 | auth | stub実装が常にOk()→認証バイパス | feature flagなしはコンパイルエラー/常に失敗 |
| 6 | otp_engine | decrypt()がKey Poolを消費 | decrypt_with_key()に分離、Pool消費なし |
| 7 | thermal_rng | エントロピー閾値が緩すぎる | Chi-square検定+バイト頻度チェック(4096B) |
| 8 | kernel_module | nf_register戻り値未確認 | 戻り値チェック+失敗時にモジュールロード失敗 |

#### HIGH (5件)
| # | 場所 | 脆弱性 | 修正 |
|---|------|--------|------|
| 9 | key_pool | Consumed後もVecに残留→メモリ肥大 | consume時にVec.remove()で完全削除 |
| 10 | key_pool | スライスコピーで残留バイト | ブロック全体をmoveし残りもdropでゼロ化 |
| 11 | auth | エラーに認証進捗(bool)を含める | エラーを単一メッセージに統一 |
| 12 | thermal_rng | exists()→open()のTOCTOU | exists()廃止、open()の結果のみで判断 |
| 13 | qhal | len==0の乱数生成を許可 | InvalidLengthエラーで即拒否 |

#### MEDIUM (3件)
| # | 場所 | 脆弱性 | 修正 |
|---|------|--------|------|
| 14 | key_pool | low_water_mark=0設定可能 | MIN_LOW_WATER_MARK(64)未満は拒否 |
| 15 | key_pool | 空Vecの鍵を追加可能 | EmptyKeyMaterialエラーで拒否 |
| 16 | key_pool | available_bytes()とacquire()のTOCTOU | 単一Mutexで原子的に操作 |
