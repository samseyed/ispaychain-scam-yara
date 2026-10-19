rule Crypto_Scam_Ispaychain_Cluster
{
    meta:
        author = "Ibtissam"
        date = "2026-10-19"
        description = "Detects reported ispaychain and related crypto staking investigation indicators"
        threat_level = "high"
        category = "crypto_scam"
        reference = "Reported OSINT and smart-contract analysis; independently verify"

    strings:
        $domain_1 = "ispaychain.com" ascii nocase
        $domain_2 = "moblus.net" ascii nocase
        $domain_3 = "mobiustrip.io" ascii nocase
        $domain_4 = "ms20.me" ascii nocase
        $domain_5 = "strip.boutique" ascii nocase

        $tls_cn = "CN=www.moblus.net" ascii nocase

        $staking_contract = "0x547c95E04b4b8e6D6956acF4d0B22E8a81F79722" ascii nocase
        $usdt_contract = "0x55d398326f99059fF775485246999027B3197955" ascii nocase
        $ms_token_contract = "0x6DC3Bcecee446633cf9C95736c07D18d9Cc046C4" ascii nocase
        $referral_contract = "0x7926fb18Bc88B5567d61c41Fd11497D3D16bce36" ascii nocase

        $owner_contract = "0x555154795ec4144d901A7530E500D8e5B2AEC2e3" ascii nocase
        $market_contract = "0x84CbC994c5D8968C1dD72e44A7e4df34F6e00711" ascii nocase
        $eco_contract = "0x35012e2876019c26296cED5c5a9c7d691BAf6340" ascii nocase
        $sink_contract = "0xc8F4285735d2cd11F59F295A594E0c9c69Fa7D4E" ascii nocase

        $approve_function = /approveUsdt|approves*\(/ ascii nocase
        $stake_function = /stakes*\(/ ascii nocase
        $allowance_check = "allowance" ascii nocase
        $million_usdt = "1000000000000000000000000" ascii
        $bsc_rpc = "bsc-dataseed.binance.org" ascii nocase
        $chain_id = /chainId|chain_id/ ascii nocase

        $payload_hash = "5c6723bcc43dc7a34ec30814782bb6cf190e6fccec7c9c004a87be7b90f76f64" ascii nocase

        $staking_flow = /allowance.{0,800}approveUsdt.{0,800}stake\s*\(/ ascii nocase

    condition:
        filesize < 20MB and
        (
            $payload_hash or
            $tls_cn or
            2 of ($domain_*) or
            3 of ($staking_contract, $usdt_contract, $ms_token_contract, $referral_contract) or
            2 of ($owner_contract, $market_contract, $eco_contract, $sink_contract) or
            ($approve_function and $stake_function and $allowance_check and $million_usdt) or
            ($bsc_rpc and $chain_id and $approve_function) or
            $staking_flow
        )
}

rule Crypto_Scam_Ispaychain_Contract_Config
{
    meta:
        author = "Ibtissam"
        date = "2026-10-19"
        description = "Detects artifacts containing the reported ispaychain BSC staking contract configuration"
        threat_level = "high"
        category = "crypto_scam"

    strings:
        $staking = "0x547c95E04b4b8e6D6956acF4d0B22E8a81F79722" ascii nocase
        $owner = "0x555154795ec4144d901A7530E500D8e5B2AEC2e3" ascii nocase
        $referral = "0x7926fb18Bc88B5567d61c41Fd11497D3D16bce36" ascii nocase
        $market = "0x84CbC994c5D8968C1dD72e44A7e4df34F6e00711" ascii nocase
        $eco = "0x35012e2876019c26296cED5c5a9c7d691BAf6340" ascii nocase
        $sink = "0xc8F4285735d2cd11F59F295A594E0c9c69Fa7D4E" ascii nocase

        $fn_owner = "owner()(address)" ascii nocase
        $fn_init = "init()(address)" ascii nocase
        $fn_queue = "queueWait()(uint40)" ascii nocase
        $fn_team = "teamDirectBps()(uint16)" ascii nocase
        $fn_liq = "liqBps()(uint16)" ascii nocase
        $fn_breaker = "circuitBreakerThreshold()(uint256)" ascii nocase
        $fn_plan = "plans(uint256)(uint128,uint128,uint128,uint32,bool)" ascii nocase

        $queue_wait = "604800" ascii
        $team_direct = "3000" ascii
        $liquidity_bps = "5000" ascii

    condition:
        filesize < 20MB and
        (
            3 of ($staking, $owner, $referral, $market, $eco, $sink) or
            3 of ($fn_owner, $fn_init, $fn_queue, $fn_team, $fn_liq, $fn_breaker, $fn_plan) or
            ($staking and $queue_wait and $team_direct and $liquidity_bps)
        )
}
