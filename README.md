# RelayRouter v2 — unguarded cleanup functions (PoC)

Proof of concept for a Relay bug bounty report: the **deployed**
RelayRouter v2 lets any contract invoked during a victim's multicall drain
the router's entire in-flight ERC20 balance via the permissionless,
reentrancy-unguarded `cleanupErc20s`.

## Target (deployed, Sourcify exact-match)

| Contract | Address (same CREATE2 address on all chains) | Chain verified on |
|---|---|---|
| ApprovalProxy v2 | `0xBBbfD134E9b44BfB5123898BA36b01dE7ab93d98` | Arbitrum One |
| RelayRouter v2 | `0xF5042e6ffaC5a625D4E7848e0b01373D8eB9e222` | Arbitrum One |
| USDC (Arbitrum) | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` | — |

RelayRouter v3 (repo HEAD, **not** deployed) adds `nonReentrant` to all four
cleanup functions — the fix for exactly this issue. The deployed v2 code has
no guard on `cleanupErc20s`, `cleanupErc20sViaCall`, `cleanupNative`, or
`cleanupNativeViaCall`; only `multicall` itself is guarded.

## What the PoC shows

A victim buys NFT #1 (listed by an innocent seller for 10,000 USDC) through
the deployed ApprovalProxy. The NFT belongs to a malicious collection.
During the victim's multicall, the collection's transfer hook re-enters
`router.cleanupErc20s` and steals **all 15,000 USDC** the victim brought
in-flight (10,000 price + 5,000 spare). The purchase still "succeeds":
the victim receives the NFT, the seller is never paid, the victim's 5,000
USDC refund silently fails (`allowFailure=true`), and the router is left
empty. A control test with an honest collection shows the same flow paying
the seller 10,000 USDC and refunding the victim 5,000 USDC.

Verified run (2026-11-16, fork L2 block 524717128):

```
[PASS] testStealInFlightFundsViaMaliciousNFT()
  USDC stolen by attacker: 15000 USDC
  Seller received: 0 USDC
  Victim refund received: 0 USDC
  Router USDC balance: 0 USDC
  Victim owns NFT #1: true
[PASS] testControlBenignCollectionPaysSellerAndRefunds()
Suite result: ok. 2 passed; 0 failed
```

## Run it

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation)
(`forge` 1.9.0 used for verification).

```bash
forge test --match-contract RouterCleanupReentrancyTest -vvv
```

By default the test forks Arbitrum One at the latest block via the free
publicnode endpoint (current state only). To reproduce at a pinned block,
use an archive RPC and set `FORK_BLOCK`:

```bash
FORK_BLOCK=524717128 forge test --match-contract RouterCleanupReentrancyTest -vvv
```

Note: `block.number` inside an Arbitrum fork is the L1 block number; the
test logs the real L2 fork block via the ArbSys precompile.

## Files

- `src/MaliciousNFT.sol` — malicious ERC721 (attack) + benign control.
- `test/RouterCleanupReentrancy.t.sol` — fork tests (attack + control).

## Scope note

This is **not** the "residual funds" case the router's threat model
excludes: the router holds **zero** balance at the start of the attack
transaction. The funds arrive mid-transaction from the victim's own flow
and are stolen mid-transaction. The exclusion covers a balance held at the
start of the attack tx; it does not cover in-flight theft during a
victim's multicall. Nothing here was executed on mainnet; all state
changes are fork-local.
