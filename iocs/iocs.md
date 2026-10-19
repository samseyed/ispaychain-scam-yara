# IOCs — ispaychain / moblus scam cluster

These are reported investigation indicators. Verify them against original evidence before treating them as confirmed malicious infrastructure.

## Domains

- `ispaychain.com`
- `www.moblus.net`
- `www.mobiustrip.io`
- `www.ms20.me`
- `www.strip.boutique`

## TLS indicators (reported; verify independently)

- Certificate CN: `www.moblus.net`
- Reported: `ispaychain.com` fails TLS certificate verification.
- Reported: the certificate also covers `mobiustrip.io`, `ms20.me`, and `strip.boutique`.

## Shared frontend payload (reported; verify against the original file)

- SHA-256: `5c6723bcc43dc7a34ec30814782bb6cf190e6fccec7c9c004a87be7b90f76f64`
- Size: `1,701,636` bytes

## BNB Smart Chain indicators

- Chain ID: `56`
- RPC: `https://bsc-dataseed.binance.org/`

### Contract addresses (reported; independently verify on-chain)

| Role | Address |
|---|---|
| Staking / spender | `0x547c95E04b4b8e6D6956acF4d0B22E8a81F79722` |
| USDT | `0x55d398326f99059fF775485246999027B3197955` |
| MS token | `0x6DC3Bcecee446633cf9C95736c07D18d9Cc046C4` |
| Referral / user | `0x7926fb18Bc88B5567d61c41Fd11497D3D16bce36` |
| Owner / init | `0x555154795ec4144d901A7530E500D8e5B2AEC2e3` |
| Market | `0x84CbC994c5D8968C1dD72e44A7e4df34F6e00711` |
| Eco | `0x35012e2876019c26296cED5c5a9c7d691BAf6340` |
| Sink | `0xc8F4285735d2cd11F59F295A594E0c9c69Fa7D4E` |

## Reported high-risk behavior (verify from transaction traces/source)

- Requests approval for `1,000,000 USDT` (`1000000000000000000000000` base units).
- Calls `approveUsdt` before `stake(amount, plan)`.
- Reported seven-day exit queue: `queueWait = 604800` seconds.
- Reported fee recipients include owner-linked market, eco, and sink addresses.
