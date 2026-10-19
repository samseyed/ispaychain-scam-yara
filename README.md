# ispaychain-scam-yara

YARA rules and indicators for the `ispaychain.com` / `moblus.net` crypto-staking scam cluster.

## Scope

This repository contains defensive detection rules for:

- Cloned scam web frontends
- TLS/certificate mismatches
- Shared JavaScript/HTML payload indicators
- BNB Smart Chain staking-contract artifacts
- High-risk USDT approval behavior

## Rules

- `rules/ispaychain_scam.yar`

## Usage

Install the YARA-CI GitHub App on this repository.
Any pushed `.yar` or `.yara` file is intended to be analyzed by the configured CI integration.

## Warning

Do not connect a wallet, approve tokens, or send funds to the addresses listed in this repository.

## Evidence note

Indicators in this repository are investigative leads and require independent verification. A YARA match alone does not prove fraud.
- Initial YARA-CI verification commit.
