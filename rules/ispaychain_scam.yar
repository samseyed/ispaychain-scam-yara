rule Crypto_Scam_Ispaychain_Contract_Config
{
    meta:
        author = "Ibtissam"
        date = "2026-10-19"
        description = "Detects artifacts exposing the ispaychain BSC staking contract configuration"
        threat_level = "high"
        category = "crypto_scam"

    strings:
        $staking = "547c95E04b4b8e6D6956acF4d0B22E8a81F79722" ascii nocase
        $owner = "555154795ec4144d901A7530E500D8e5B2AEC2e3" ascii nocase
        $referral = "7926fb18Bc88B5567d61c41Fd11497D3D16bce36" ascii nocase
        $market = "84CbC994c5D8968C1dD72e44A7e4df34F6e00711" ascii nocase
        $eco = "35012e2876019c26296cED5c5a9c7d691BAf6340" ascii nocase
        $sink = "c8F4285735d2cd11F59F295A594E0c9c69Fa7D4E" ascii nocase

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
