// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {HyperionGuard} from "../src/HyperionGuard.sol";
import {GuardedExecutor} from "../src/GuardedExecutor.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// Stands in for a DEX: records calls, and can try to re-enter the executor.
contract MockVenue {
    uint256 public calls;
    GuardedExecutor public reenterInto;
    bytes public reenterPayload;

    function trade(uint256 amount) external returns (uint256) {
        calls += 1;
        if (address(reenterInto) != address(0)) {
            (bool ok,) = address(reenterInto).call(reenterPayload);
            require(!ok, "reentry should fail");
        }
        return amount * 2;
    }

    function fail() external pure {
        revert("venue says no");
    }

    function armReentry(GuardedExecutor exec, bytes calldata payload) external {
        reenterInto = exec;
        reenterPayload = payload;
    }
}

contract HyperionGuardTest is Test {
    HyperionGuard guard;
    MockUSDC usdc;
    MockVenue venue;
    GuardedExecutor exec;

    address admin = makeAddr("admin");
    address owner = makeAddr("owner");
    address guardian = makeAddr("guardian");
    address agent = makeAddr("agent");
    address stranger = makeAddr("stranger");
    uint256 signerKey = 0xA11CE;
    address signer;

    HyperionGuard.Policy policy = HyperionGuard.Policy({
        maxOrderNotional: 1_000e6, maxDailyNotional: 5_000e6, collarBps: 200, maxOrdersPerMinute: 10
    });

    function setUp() public {
        vm.warp(1_790_000_000);
        signer = vm.addr(signerKey);
        guard = new HyperionGuard(admin, signer);
        vm.prank(owner);
        guard.registerAgent(agent, policy, guardian);

        usdc = new MockUSDC();
        venue = new MockVenue();
        exec = new GuardedExecutor(guard, owner, agent);
        vm.prank(owner);
        exec.setAllowedTarget(address(venue), true);
        usdc.mint(address(exec), 10_000e6);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    function verdict(bytes32 orderHash, bool approved) internal view returns (HyperionGuard.Verdict memory v) {
        v = HyperionGuard.Verdict({
            agent: agent,
            orderHash: orderHash,
            approved: approved,
            reason: approved ? 0 : 3,
            policyVersion: guard.agentOf(agent).policyVersion,
            seq: 1,
            expiresAt: uint64(block.timestamp + 60)
        });
    }

    function sign(HyperionGuard.Verdict memory v, uint256 key) internal view returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(key, guard.hashVerdict(v));
        return abi.encodePacked(r, s, vv);
    }

    function approvedFor(bytes memory data, uint256 notional)
        internal
        view
        returns (HyperionGuard.Verdict memory v, bytes memory sig)
    {
        v = verdict(exec.orderHash(address(venue), data, notional, exec.nonce()), true);
        sig = sign(v, signerKey);
    }

    // ── registration & policy ────────────────────────────────────────────────

    function test_registerStoresOwnerPolicyAndVersion() public view {
        HyperionGuard.Agent memory a = guard.agentOf(agent);
        assertEq(a.owner, owner);
        assertEq(a.guardian, guardian);
        assertEq(a.policyVersion, 1);
        assertEq(a.policy.maxOrderNotional, 1_000e6);
        assertFalse(a.killed);
    }

    function test_cannotRegisterTwice() public {
        vm.prank(stranger);
        vm.expectRevert(HyperionGuard.AgentExists.selector);
        guard.registerAgent(agent, policy, address(0));
    }

    function test_invalidPoliciesRejected() public {
        HyperionGuard.Policy memory p = policy;
        p.maxDailyNotional = p.maxOrderNotional - 1; // daily below single order
        vm.expectRevert(HyperionGuard.InvalidPolicy.selector);
        guard.registerAgent(makeAddr("a2"), p, address(0));
        p = policy;
        p.collarBps = 5_001;
        vm.expectRevert(HyperionGuard.InvalidPolicy.selector);
        guard.registerAgent(makeAddr("a3"), p, address(0));
    }

    function test_onlyOwnerChangesPolicy_andVersionBumps() public {
        vm.prank(agent); // the agent can't loosen its own limits
        vm.expectRevert(HyperionGuard.NotAgentOwner.selector);
        guard.setPolicy(agent, policy);
        vm.prank(owner);
        guard.setPolicy(agent, policy);
        assertEq(guard.agentOf(agent).policyVersion, 2);
    }

    // ── kill switch ──────────────────────────────────────────────────────────

    function test_ownerOrGuardianCanKill_strangerAndAgentCannot() public {
        vm.prank(stranger);
        vm.expectRevert(HyperionGuard.NotOwnerOrGuardian.selector);
        guard.kill(agent);
        vm.prank(agent);
        vm.expectRevert(HyperionGuard.NotOwnerOrGuardian.selector);
        guard.kill(agent);
        vm.prank(guardian);
        guard.kill(agent);
        assertTrue(guard.agentOf(agent).killed);
    }

    function test_guardianCannotRevive_ownerCan_andOldVerdictsStayDead() public {
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(abi.encodeCall(MockVenue.trade, (1)), 100e6);
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.Valid));

        vm.prank(guardian);
        guard.kill(agent);
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.Killed));

        vm.prank(guardian);
        vm.expectRevert(HyperionGuard.NotAgentOwner.selector);
        guard.revive(agent);

        vm.prank(owner);
        guard.revive(agent);
        // revived, but the pre-kill verdict was for the old policy version
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.StalePolicy));
    }

    // ── verdict checks ───────────────────────────────────────────────────────

    function test_checkStatuses() public {
        bytes32 h = keccak256("order");
        HyperionGuard.Verdict memory v = verdict(h, true);

        assertEq(uint8(guard.check(v, sign(v, signerKey))), uint8(HyperionGuard.Status.Valid));
        assertEq(uint8(guard.check(v, sign(v, 0xBAD))), uint8(HyperionGuard.Status.BadSignature));
        assertEq(uint8(guard.check(v, hex"1234")), uint8(HyperionGuard.Status.BadSignature));

        HyperionGuard.Verdict memory rejected = verdict(h, false);
        assertEq(uint8(guard.check(rejected, sign(rejected, signerKey))), uint8(HyperionGuard.Status.NotApproved));

        // memory structs alias on assignment: build each variant fresh
        HyperionGuard.Verdict memory unknown = verdict(h, true);
        unknown.agent = stranger;
        assertEq(uint8(guard.check(unknown, sign(unknown, signerKey))), uint8(HyperionGuard.Status.UnknownAgent));

        HyperionGuard.Verdict memory tooLong = verdict(h, true);
        tooLong.expiresAt = uint64(block.timestamp + guard.MAX_VERDICT_TTL() + 1);
        assertEq(uint8(guard.check(tooLong, sign(tooLong, signerKey))), uint8(HyperionGuard.Status.Expired));

        bytes memory sig = sign(v, signerKey);
        vm.warp(v.expiresAt + 1);
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.Expired));
    }

    function test_tamperingWithAnySignedFieldBreaksTheSignature() public view {
        HyperionGuard.Verdict memory v = verdict(keccak256("order"), true);
        bytes memory sig = sign(v, signerKey);
        v.orderHash = keccak256("a different order");
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.BadSignature));
    }

    function test_rotatingTheSignerInvalidatesOutstandingVerdicts() public {
        HyperionGuard.Verdict memory v = verdict(keccak256("order"), true);
        bytes memory sig = sign(v, signerKey);
        vm.prank(admin);
        guard.setGuardSigner(vm.addr(0xB0B));
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.BadSignature));
    }

    function test_policyChangeInvalidatesOutstandingVerdicts() public {
        HyperionGuard.Verdict memory v = verdict(keccak256("order"), true);
        bytes memory sig = sign(v, signerKey);
        vm.prank(owner);
        guard.setPolicy(agent, policy);
        assertEq(uint8(guard.check(v, sig)), uint8(HyperionGuard.Status.StalePolicy));
    }

    // ── audit trail ──────────────────────────────────────────────────────────

    function test_anchorsMustBeContiguousAndFromTheSigner() public {
        vm.prank(stranger);
        vm.expectRevert(HyperionGuard.NotGuardSigner.selector);
        guard.anchor(1, 10, bytes32(uint256(1)));

        vm.startPrank(signer);
        guard.anchor(1, 10, bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(HyperionGuard.BadSequence.selector, uint64(11)));
        guard.anchor(12, 20, bytes32(uint256(2))); // a gap
        vm.expectRevert(abi.encodeWithSelector(HyperionGuard.BadSequence.selector, uint64(11)));
        guard.anchor(11, 10, bytes32(uint256(2))); // backwards
        guard.anchor(11, 20, bytes32(uint256(2)));
        vm.stopPrank();
        assertEq(guard.lastAnchoredSeq(), 20);
    }

    // ── executor ─────────────────────────────────────────────────────────────

    function test_executeWithAValidVerdict() public {
        bytes memory data = abi.encodeCall(MockVenue.trade, (21));
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, 100e6);
        vm.prank(agent);
        bytes memory ret = exec.execute(address(venue), data, 100e6, v, sig);
        assertEq(abi.decode(ret, (uint256)), 42);
        assertEq(venue.calls(), 1);
        assertEq(exec.nonce(), 1);
    }

    function test_aVerdictCannotBeReplayed() public {
        bytes memory data = abi.encodeCall(MockVenue.trade, (1));
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, 100e6);
        vm.startPrank(agent);
        exec.execute(address(venue), data, 100e6, v, sig);
        vm.expectRevert(GuardedExecutor.WrongOrder.selector); // nonce moved on
        exec.execute(address(venue), data, 100e6, v, sig);
        vm.stopPrank();
    }

    function test_theCallCannotChangeAfterApproval() public {
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(abi.encodeCall(MockVenue.trade, (1)), 100e6);
        vm.startPrank(agent);
        vm.expectRevert(GuardedExecutor.WrongOrder.selector);
        exec.execute(address(venue), abi.encodeCall(MockVenue.trade, (1_000_000)), 100e6, v, sig);
        vm.expectRevert(GuardedExecutor.WrongOrder.selector); // same call, bigger declared notional
        exec.execute(address(venue), abi.encodeCall(MockVenue.trade, (1)), 900e6, v, sig);
        vm.stopPrank();
    }

    function test_onlyTheAgent_onlyListedTargets() public {
        bytes memory data = abi.encodeCall(MockVenue.trade, (1));
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, 1e6);
        vm.prank(stranger);
        vm.expectRevert(GuardedExecutor.NotAgent.selector);
        exec.execute(address(venue), data, 1e6, v, sig);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(GuardedExecutor.TargetNotAllowed.selector, address(usdc)));
        exec.execute(address(usdc), data, 1e6, v, sig);
    }

    function test_killedAgentCannotExecute() public {
        bytes memory data = abi.encodeCall(MockVenue.trade, (1));
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, 1e6);
        vm.prank(guardian);
        guard.kill(agent);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(GuardedExecutor.VerdictRejected.selector, HyperionGuard.Status.Killed));
        exec.execute(address(venue), data, 1e6, v, sig);
    }

    function test_rejectedVerdictCannotExecute() public {
        bytes memory data = abi.encodeCall(MockVenue.trade, (1));
        HyperionGuard.Verdict memory v = verdict(exec.orderHash(address(venue), data, 1e6, 0), false);
        bytes memory sig = sign(v, signerKey);
        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(GuardedExecutor.VerdictRejected.selector, HyperionGuard.Status.NotApproved)
        );
        exec.execute(address(venue), data, 1e6, v, sig);
    }

    function test_failedCallRevertsAndDoesNotSpendTheNonce() public {
        bytes memory data = abi.encodeCall(MockVenue.fail, ());
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, 1e6);
        vm.prank(agent);
        vm.expectRevert();
        exec.execute(address(venue), data, 1e6, v, sig);
        assertEq(exec.nonce(), 0);
    }

    function test_reentryIsBlocked() public {
        bytes memory data = abi.encodeCall(MockVenue.trade, (1));
        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, 1e6);
        venue.armReentry(exec, abi.encodeCall(GuardedExecutor.execute, (address(venue), data, 1e6, v, sig)));
        vm.prank(agent);
        exec.execute(address(venue), data, 1e6, v, sig); // the venue asserts its re-entry failed
        assertEq(venue.calls(), 1);
    }

    function test_ownerCanAlwaysWithdraw_othersCannot() public {
        vm.prank(guardian);
        guard.kill(agent);
        vm.prank(agent);
        vm.expectRevert(GuardedExecutor.NotOwner.selector);
        exec.withdraw(usdc, agent, 1);
        vm.prank(owner);
        exec.withdraw(usdc, owner, 10_000e6);
        assertEq(usdc.balanceOf(owner), 10_000e6);
    }

    // ── vectors shared with the Python service (tests/test_guard.py) ─────────

    /// The service signs what the contract verifies: the same digest from
    /// the same verdict and domain. If this breaks, every signature fails.
    function test_verdictDigestMatchesThePythonService() public view {
        assertEq(address(guard), 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f); // first CREATE from the test contract
        HyperionGuard.Verdict memory v = HyperionGuard.Verdict({
            agent: address(0xA1A1a1a1A1A1A1A1A1a1a1a1a1a1A1A1a1A1a1a1),
            orderHash: 0xabababababababababababababababababababababababababababababababab,
            approved: true,
            reason: 0,
            policyVersion: 1,
            seq: 7,
            expiresAt: 1_790_000_060
        });
        assertEq(guard.hashVerdict(v), 0x1aa970729120b515155762c75c9a2c80cd6ee2063c364f6d5b2994decb50ba07);
    }

    /// The service's executor order hash is GuardedExecutor.orderHash's encoding.
    function test_executorOrderHashEncodingMatchesThePythonService() public pure {
        bytes32 h = keccak256(
            abi.encode(
                uint256(31337),
                address(0xe0E0e0e0e0E0E0e0E0e0e0e0e0e0E0e0e0e0e0e0),
                address(0xD0D0d0d0d0D0D0d0D0D0D0D0d0D0d0d0d0d0D0D0),
                keccak256(hex"deadbeef"),
                uint256(650_000_000),
                uint256(4)
            )
        );
        assertEq(h, 0x97e53d86177a34484050182064ab45b43938f14d1e9cea6af687f174b317dee0);
    }

    /// Whatever order is approved, a different call or notional never passes.
    function testFuzz_onlyTheExactApprovedCallExecutes(uint256 approvedAmt, uint256 triedAmt, uint256 notional) public {
        vm.assume(approvedAmt != triedAmt);
        approvedAmt = bound(approvedAmt, 0, 1e30);
        triedAmt = bound(triedAmt, 0, 1e30);
        vm.assume(approvedAmt != triedAmt);
        (HyperionGuard.Verdict memory v, bytes memory sig) =
            approvedFor(abi.encodeCall(MockVenue.trade, (approvedAmt)), notional);
        vm.prank(agent);
        vm.expectRevert(GuardedExecutor.WrongOrder.selector);
        exec.execute(address(venue), abi.encodeCall(MockVenue.trade, (triedAmt)), notional, v, sig);
    }

    // ── calldata notional decoder tests ─────────────────────────────────────

    function test_calldataNotionalDecoder_demoVenue() public view {
        // Place order: 0.01 BTC (1_000_000 in 1e8) at $65,000 (65_000e8 in 1e8)
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("placeOrder(bytes32,bool,uint256,uint256)")),
            bytes32("BTC-USD"),
            true,
            uint256(1_000_000),      // 0.01 BTC
            uint256(65_000e8)        // $65,000 / BTC
        );
        // (1e6 * 65_000e8) / 1e10 = 650_000_000 micro-USDC ($650.00)
        uint256 decoded = exec.decodeCalldataNotional(data);
        assertEq(decoded, 650_000_000);
    }

    function test_calldataNotionalDecoder_underreportedNotionalReverts() public {
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("placeOrder(bytes32,bool,uint256,uint256)")),
            bytes32("BTC-USD"),
            true,
            uint256(1_000_000),      // 0.01 BTC
            uint256(65_000e8)        // $65,000 -> 650_000_000 notional
        );
        uint256 declaredNotional = 100_000_000; // Agent lies: declares $100 instead of $650

        (HyperionGuard.Verdict memory v, bytes memory sig) = approvedFor(data, declaredNotional);
        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(
                GuardedExecutor.NotionalUnderreported.selector,
                uint256(650_000_000),
                uint256(100_000_000)
            )
        );
        exec.execute(address(venue), data, declaredNotional, v, sig);
    }

    function test_calldataNotionalDecoder_uniswapV3AndV2() public view {
        // Uniswap V3 exactInputSingle
        bytes memory v3Data = abi.encodeWithSelector(
            0x414bacae,
            address(0x1),
            address(0x2),
            uint24(3000),
            address(0x3),
            uint256(5_000e6),        // amountIn: $5,000 USDC
            uint256(1e18),
            uint160(0)
        );
        assertEq(exec.decodeCalldataNotional(v3Data), 5_000e6);

        // Uniswap V2 swapExactTokensForTokens
        address[] memory path = new address[](2);
        path[0] = address(0x1);
        path[1] = address(0x2);
        bytes memory v2Data = abi.encodeWithSelector(
            0x38ed1739,
            uint256(2_500e6),        // amountIn: $2,500 USDC
            uint256(1e18),
            path,
            address(0x3),
            uint256(block.timestamp + 1000)
        );
        assertEq(exec.decodeCalldataNotional(v2Data), 2_500e6);
    }
}
