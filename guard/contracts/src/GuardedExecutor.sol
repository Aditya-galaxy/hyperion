// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {HyperionGuard} from "./HyperionGuard.sol";

/// @title GuardedExecutor
/// @notice A wallet an autonomous trading agent can trade from, but only
/// with the Guard's approval for that exact call.
///
/// The owner funds it and lists the contracts it may call (a DEX router, a
/// token to approve). The agent calls `execute` with the call, its declared
/// USDC notional, and a Guard verdict. The verdict must cover the hash of
/// exactly that call at the current nonce, and `HyperionGuard.check` must
/// say it's live. So the agent can't reuse an approval, change the call
/// after approval, call anything unlisted, or act at all once killed.
///
/// What this doesn't do: read the notional out of arbitrary calldata. The
/// agent declares it, and the Guard checks the declared figure against the
/// call it's shown. The target allow-list bounds what a lie could reach.
contract GuardedExecutor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    HyperionGuard public immutable guard;
    address public immutable owner;
    address public immutable agent;

    uint256 public nonce;
    mapping(address target => bool) public allowedTarget;

    event TargetAllowed(address indexed target, bool allowed);
    event Executed(uint256 indexed nonce, address indexed target, uint256 notional, uint64 verdictSeq);
    event Withdrawn(address indexed token, address indexed to, uint256 amount);

    error NotOwner();
    error NotAgent();
    error TargetNotAllowed(address target);
    error WrongOrder();
    error VerdictRejected(HyperionGuard.Status status);
    error CallFailed(bytes returnData);
    error NotionalUnderreported(uint256 decodedNotional, uint256 declaredNotional);

    constructor(HyperionGuard guard_, address owner_, address agent_) {
        guard = guard_;
        owner = owner_;
        agent = agent_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function setAllowedTarget(address target, bool allowed) external onlyOwner {
        allowedTarget[target] = allowed;
        emit TargetAllowed(target, allowed);
    }

    /// The owner can always take funds out, whatever the agent's state.
    function withdraw(IERC20 token, address to, uint256 amount) external onlyOwner {
        token.safeTransfer(to, amount);
        emit Withdrawn(address(token), to, amount);
    }

    /// @notice Inspects target calldata to deterministically extract notional for supported DEX interfaces.
    /// @dev Decodes:
    ///   - DemoVenue.placeOrder(bytes32,bool,uint256,uint256): qty (1e8) * price (1e8) / 1e10 -> micro-USDC
    ///   - Uniswap V3 exactInputSingle((address,address,uint24,address,uint256,uint256,uint160)): amountIn
    ///   - Uniswap V3 exactInputSingle (SwapRouter02 struct): amountIn
    ///   - Uniswap V2 swapExactTokensForTokens(uint256,uint256,address[],address,uint256): amountIn
    ///   - ERC20 transfer(address,uint256): amount
    function decodeCalldataNotional(bytes calldata data) public pure returns (uint256) {
        if (data.length < 4) return 0;
        bytes4 selector = bytes4(data[:4]);

        // 1. DemoVenue.placeOrder(bytes32 symbol, bool buy, uint256 qty, uint256 price)
        // selector: bytes4(keccak256("placeOrder(bytes32,bool,uint256,uint256)"))
        if (selector == bytes4(keccak256("placeOrder(bytes32,bool,uint256,uint256)"))) {
            if (data.length >= 4 + 32 * 4) {
                uint256 qty = abi.decode(data[68:100], (uint256));
                uint256 price = abi.decode(data[100:132], (uint256));
                return (qty * price) / 1e10; // 1e8 * 1e8 = 1e16 -> / 1e10 = 1e6 micro-USDC
            }
        }

        // 2. Uniswap V3 exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
        if (selector == 0x414bacae || selector == 0x04e45aaf) {
            if (data.length >= 4 + 32 * 7) {
                return abi.decode(data[132:164], (uint256));
            }
        }

        // 3. Uniswap V2 swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
        if (selector == 0x38ed1739) {
            if (data.length >= 4 + 32) {
                return abi.decode(data[4:36], (uint256));
            }
        }

        // 4. ERC20 transfer(address,uint256)
        if (selector == 0xa9059cbb) {
            if (data.length >= 4 + 64) {
                return abi.decode(data[36:68], (uint256));
            }
        }

        return 0;
    }

    /// The hash the Guard signs for a call. Binds the chain, this wallet,
    /// the target, the calldata, the declared notional and the nonce.
    function orderHash(address target, bytes calldata data, uint256 notional, uint256 nonce_)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), target, keccak256(data), notional, nonce_));
    }

    function execute(
        address target,
        bytes calldata data,
        uint256 notional,
        HyperionGuard.Verdict calldata verdict,
        bytes calldata signature
    ) external nonReentrant returns (bytes memory) {
        if (msg.sender != agent) revert NotAgent();
        if (!allowedTarget[target]) revert TargetNotAllowed(target);

        // On-chain calldata notional firewall: ensure agent did not under-report notional
        uint256 decodedNotional = decodeCalldataNotional(data);
        if (decodedNotional > 0 && notional < decodedNotional) {
            revert NotionalUnderreported(decodedNotional, notional);
        }

        if (verdict.agent != agent || verdict.orderHash != orderHash(target, data, notional, nonce)) {
            revert WrongOrder();
        }
        HyperionGuard.Status status = guard.check(verdict, signature);
        if (status != HyperionGuard.Status.Valid) revert VerdictRejected(status);

        uint256 used = nonce;
        unchecked {
            nonce = used + 1; // before the call: a reentrant replay sees the next nonce
        }
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) revert CallFailed(ret);
        emit Executed(used, target, notional, verdict.seq);
        return ret;
    }
}
