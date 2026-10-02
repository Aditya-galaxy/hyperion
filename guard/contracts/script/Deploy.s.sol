// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {HyperionGuard} from "../src/HyperionGuard.sol";
import {GuardedExecutor} from "../src/GuardedExecutor.sol";
import {DemoVenue} from "../src/DemoVenue.sol";

/// Deploys HyperionGuard with the broadcasting account as admin.
///
///   GUARD_SIGNER=0x… forge script script/Deploy.s.sol \
///     --rpc-url arc_testnet --account guard-owner --broadcast
///
/// Use an encrypted keystore (`cast wallet import guard-owner --interactive`),
/// never a private key on the command line.
contract Deploy is Script {
    function run() external returns (HyperionGuard guard) {
        address signer = vm.envAddress("GUARD_SIGNER");
        vm.startBroadcast();
        guard = new HyperionGuard(msg.sender, signer);
        vm.stopBroadcast();
        console.log("HyperionGuard", address(guard));
        console.log("admin", msg.sender);
        console.log("guardSigner", signer);
    }
}

/// Sets up the demo against a deployed Guard: registers the agent with a
/// policy (the broadcaster becomes its owner), deploys a GuardedExecutor for
/// it and a DemoVenue, and lists the venue as an allowed target.
///
///   GUARD=0x… AGENT=0x… [GUARDIAN=0x…] forge script script/Deploy.s.sol:DemoSetup \
///     --rpc-url arc_testnet --account guard-owner --broadcast
contract DemoSetup is Script {
    function run() external returns (GuardedExecutor exec, DemoVenue venue) {
        HyperionGuard guard = HyperionGuard(vm.envAddress("GUARD"));
        address agent = vm.envAddress("AGENT");
        address guardian = vm.envOr("GUARDIAN", address(0));
        HyperionGuard.Policy memory policy = HyperionGuard.Policy({
            maxOrderNotional: uint64(vm.envOr("MAX_ORDER_USDC", uint256(1_000)) * 1e6),
            maxDailyNotional: uint64(vm.envOr("MAX_DAILY_USDC", uint256(5_000)) * 1e6),
            collarBps: uint16(vm.envOr("COLLAR_BPS", uint256(200))),
            maxOrdersPerMinute: uint16(vm.envOr("MAX_ORDERS_PER_MIN", uint256(5)))
        });

        vm.startBroadcast();
        guard.registerAgent(agent, policy, guardian);
        address usdcToken = vm.envOr("USDC", address(0));
        exec = new GuardedExecutor(guard, msg.sender, agent, usdcToken);
        venue = new DemoVenue();
        exec.setAllowedTarget(address(venue), true);
        vm.stopBroadcast();

        console.log("agent", agent);
        console.log("GuardedExecutor", address(exec));
        console.log("DemoVenue", address(venue));
    }
}
