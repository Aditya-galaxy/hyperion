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
/// Includes an on-chain calldata notional decoder to ensure the agent does not
/// under-report trade notional compared to the actual transaction payload.
contract GuardedExecutor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    HyperionGuard public immutable guard;
    address public immutable owner;
    address public immutable agent;
    address public immutable usdc;

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

    constructor(HyperionGuard guard_, address owner_, address agent_, address usdc_) {
        guard = guard_;
        owner = owner_;
        agent = agent_;
        usdc = usdc_;
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
    ///   - Uniswap V3 exactInputSingle (SwapRouter01: 0x414bf389): amountIn is word 5 (bytes 164..196)
    ///   - Uniswap V3 exactInputSingle (SwapRouter02: 0x04e45aaf): amountIn is word 4 (bytes 132..164)
    ///   - Uniswap V2 swapExactTokensForTokens(uint256,uint256,address[],address,uint256): amountIn
    ///   - ERC20 transfer(address,uint256): amount
    ///
    /// NOTE: For token swaps, amountIn is in the input token's units and is only directly
    /// comparable to declared USDC notional when tokenIn is USDC. If usdc != address(0)
    /// and tokenIn != usdc, returns 0 so un-convertible notional is not misread.
    function decodeCalldataNotional(bytes calldata data) public view returns (uint256) {
        if (data.length < 4) return 0;
        bytes4 selector = bytes4(data[:4]);

        // 1. DemoVenue.placeOrder(bytes32 symbol, bool buy, uint256 qty, uint256 price)
        if (selector == bytes4(keccak256("placeOrder(bytes32,bool,uint256,uint256)"))) {
            if (data.length >= 4 + 32 * 4) {
                uint256 qty = abi.decode(data[68:100], (uint256));
                uint256 price = abi.decode(data[100:132], (uint256));
                return (qty * price) / 1e10; // 1e8 * 1e8 = 1e16 -> / 1e10 = 1e6 micro-USDC
            }
        }

        // 2. Uniswap V3 exactInputSingle
        // SwapRouter01 (0x414bf389):
        //   struct ExactInputSingleParams {
        //       address tokenIn;           // word 0 (bytes 4..36)
        //       address tokenOut;          // word 1 (bytes 36..68)
        //       uint24 fee;                // word 2 (bytes 68..100)
        //       address recipient;         // word 3 (bytes 100..132)
        //       uint256 deadline;          // word 4 (bytes 132..164)
        //       uint256 amountIn;          // word 5 (bytes 164..196)
        //       uint256 amountOutMinimum;  // word 6 (bytes 196..228)
        //       uint160 sqrtPriceLimitX96; // word 7 (bytes 228..260)
        //   }
        if (selector == 0x414bf389) {
            if (data.length >= 4 + 32 * 8) {
                address tokenIn = abi.decode(data[4:36], (address));
                if (usdc != address(0) && tokenIn != usdc) return 0;
                return abi.decode(data[164:196], (uint256));
            }
        }

        // SwapRouter02 (0x04e45aaf):
        //   struct ExactInputSingleParams {
        //       address tokenIn;           // word 0 (bytes 4..36)
        //       address tokenOut;          // word 1 (bytes 36..68)
        //       uint24 fee;                // word 2 (bytes 68..100)
        //       address recipient;         // word 3 (bytes 100..132)
        //       uint256 amountIn;          // word 4 (bytes 132..164)
        //       uint256 amountOutMinimum;  // word 5 (bytes 164..196)
        //       uint160 sqrtPriceLimitX96; // word 6 (bytes 196..228)
        //   }
        if (selector == 0x04e45aaf) {
            if (data.length >= 4 + 32 * 7) {
                address tokenIn = abi.decode(data[4:36], (address));
                if (usdc != address(0) && tokenIn != usdc) return 0;
                return abi.decode(data[132:164], (uint256));
            }
        }

        // 3. Uniswap V2 swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
        // selector: 0x38ed1739
        if (selector == 0x38ed1739) {
            if (data.length >= 4 + 32 * 5) {
                if (usdc != address(0)) {
                    uint256 pathOffset = abi.decode(data[68:100], (uint256));
                    if (data.length >= 4 + pathOffset + 64) {
                        address tokenIn = abi.decode(data[4 + pathOffset + 32:4 + pathOffset + 64], (address));
                        if (tokenIn != usdc) return 0;
                    }
                }
                return abi.decode(data[4:36], (uint256));
            }
        }

        // 4. ERC20 transfer(address,uint256)
        // selector: 0xa9059cbb
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
