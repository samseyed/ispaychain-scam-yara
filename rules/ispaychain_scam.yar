// Improved version - reduced false positives - 2026-10-22
import "hash"

rule Crypto_Scam_Ispaychain_Cluster
{
    meta:
        author      = "Ibtissam"
        date        = "2026-10-22"
        description = "Detects ispaychain.com / moblus.net crypto-staking scam frontend and payload indicators"
        threat_level = "high"
        category    = "crypto_scam"
        reference   = "https://github.com/samseyed/ispaychain-scam-yara"

    strings:
        $domain_1 = "ispaychain.com" ascii nocase
        $domain_2 = "moblus.net" ascii nocase
        $domain_3 = "mobiustrip.io" ascii nocase
        $domain_4 = "ms20.me" ascii nocase
        $domain_5 = "strip.boutique" ascii nocase

        $tls_cn   = "CN=www.moblus.net" ascii nocase
        $payload_hash = "5c6723bcc43dc7a34ec30814782bb6cf190e6fccec7c9c004a87be7b90f76f64" ascii nocase

        $approve  = "approveUsdt" ascii nocase
        $stake    = "stake(" ascii nocase
        $million  = "1000000000000000000000000" ascii

    condition:
        filesize < 20MB and
        (
            $payload_hash or
            $tls_cn or
            2 of ($domain_*) or
            ($approve and $stake and $million)
        )
}

rule Crypto_Scam_Ispaychain_Contract_Config
{
    meta:
        author      = "Ibtissam"
        date        = "2026-10-22"
        description = "Detects BNB Smart Chain staking contract configuration artifacts linked to the ispaychain cluster"
        threat_level = "high"
        category    = "crypto_scam"
        reference   = "https://github.com/samseyed/ispaychain-scam-yara"

    strings:
        $staking   = "547c95E04b4b8e6D6956acF4d0B22E8a81F79722" ascii nocase
        $owner     = "555154795ec4144d901A7530E500D8e5B2AEC2e3" ascii nocase
        $referral  = "7926fb18Bc88B5567d61c41Fd11497D3D16bce36" ascii nocase
        $market    = "84CbC994c5D8968C1dD72e44A7e4df34F6e00711" ascii nocase
        $eco       = "35012e2876019c26296cED5c5a9c7d691BAf6340" ascii nocase
        $sink      = "c8F4285735d2cd11F59F295A594E0c9c69Fa7D4E" ascii nocase
        $init      = "F44C7a2B70a8ECe1fe4f599C0b77F19734B01acA" ascii nocase

        $fn_owner  = "owner()(address)" ascii nocase
        $fn_queue  = "queueWait()(uint40)" ascii nocase
        $fn_breaker = "circuitBreakerThreshold()(uint256)" ascii nocase
        $fn_plan   = "plans(uint256)(uint128,uint128,uint128,uint32,bool)" ascii nocase

        $queue_wait   = "604800" ascii
        $team_direct  = "3000" ascii
        $liquidity_bps = "5000" ascii

    condition:
        filesize < 20MB and
        (
            3 of ($staking, $owner, $referral, $market, $eco, $sink, $init) or
            3 of ($fn_owner, $fn_queue, $fn_breaker, $fn_plan) or
            ($staking and $queue_wait and $team_direct and $liquidity_bps)
        )
}

rule Crypto_Scam_Ispaychain_AWS_Infrastructure
{
    meta:
        author      = "Ibtissam"
        date        = "2026-10-22"
        description = "Detects shared AWS EC2 Tokyo hosting indicators associated with the cluster (requires multiple matches)"
        threat_level = "high"
        category    = "crypto_scam"
        reference   = "https://github.com/samseyed/ispaychain-scam-yara"

    strings:
        $ip          = "57.182.164.182" ascii
        $tls_partial = "E4A1477BF5DF" ascii nocase

    condition:
        2 of them
}

rule Ispaychain_Exact_Payload_SHA256
{
    meta:
        author      = "Ibtissam"
        date        = "2026-10-22"
        description = "Exact SHA-256 match for the known 1,701,636-byte frontend/payload sample"
        threat_level = "high"
        category    = "crypto_scam"
        reference   = "https://github.com/samseyed/ispaychain-scam-yara"

    condition:
        filesize == 1701636 and
        hash.sha256(0, filesize) == "5c6723bcc43dc7a34ec30814782bb6cf190e6fccec7c9c004a87be7b90f76f64"
}
