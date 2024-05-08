// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.4;

import {Test} from "forge-std/Test.sol";
import {Registry} from "../src/Registry.sol";
import {MockNode} from "./mocks/MockNode.sol";
import {LibDeploy} from "./lib/LibDeploy.sol";
import {Inbox, InboxItem} from "../src/Inbox.sol";
import {BaseConsumer} from "../src/consumer/Base.sol";
import {MockProtocol} from "./mocks/MockProtocol.sol";
import {Allowlist} from "../src/pattern/Allowlist.sol";
import {DeliveredOutput} from "./mocks/consumer/Base.sol";
import {EIP712Coordinator} from "../src/EIP712Coordinator.sol";
import {Coordinator, Subscription} from "../src/Coordinator.sol";
import {MockCallbackConsumer} from "./mocks/consumer/Callback.sol";
import {MockSubscriptionConsumer} from "./mocks/consumer/Subscription.sol";
import {MockAllowlistSubscriptionConsumer} from "./mocks/consumer/AllowlistSubscription.sol";

/// @title ICoordinatorEvents
/// @notice Events emitted by Coordinator
interface ICoordinatorEvents {
    event SubscriptionCreated(uint32 indexed id);
    event SubscriptionCancelled(uint32 indexed id);
    event SubscriptionFulfilled(uint32 indexed id, address indexed node);
}

/// @title CoordinatorConstants
/// @notice Base constants setup to inherit for Coordinator subtests
abstract contract CoordinatorConstants {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mock compute container ID
    string internal constant MOCK_CONTAINER_ID = "container";

    /// @notice Mock compute container ID hashed
    bytes32 internal constant HASHED_MOCK_CONTAINER_ID = keccak256(abi.encode(MOCK_CONTAINER_ID));

    /// @notice Mock container inputs
    bytes internal constant MOCK_CONTAINER_INPUTS = "inputs";

    /// @notice Mock delivered container input
    /// @dev Example of a hashed input (encoding hash(MOCK_CONTAINER_INPUTS) into input) field
    bytes internal constant MOCK_INPUT = abi.encode(keccak256(abi.encode(MOCK_CONTAINER_INPUTS)));

    /// @notice Mock delivered container compute output
    bytes internal constant MOCK_OUTPUT = "output";

    /// @notice Mock delivered proof
    bytes internal constant MOCK_PROOF = "proof";

    /// @notice Mock protocol fee (5.11%)
    uint16 internal constant MOCK_PROTOCOL_FEE = 511;

    /// @notice Zero address
    address internal constant ZERO_ADDRESS = address(0);

    /// @notice Mock empty payment token
    address internal constant NO_PAYMENT_TOKEN = ZERO_ADDRESS;

    /// @notice Mock empty wallet
    address internal constant NO_WALLET = ZERO_ADDRESS;

    /// @notice Mock empty prover contract
    address internal constant NO_PROVER = ZERO_ADDRESS;
}

/// @title CoordinatorTest
/// @notice Base setup to inherit for Coordinator subtests
abstract contract CoordinatorTest is Test, CoordinatorConstants, ICoordinatorEvents {
    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Mock protocol wallet
    MockProtocol internal PROTOCOL;

    /// @notice Coordinator
    Coordinator internal COORDINATOR;

    /// @notice Inbox
    Inbox internal INBOX;

    /// @notice Mock node (Alice)
    MockNode internal ALICE;

    /// @notice Mock node (Bob)
    MockNode internal BOB;

    /// @notice Mock node (Charlie)
    MockNode internal CHARLIE;

    /// @notice Mock callback consumer
    MockCallbackConsumer internal CALLBACK;

    /// @notice Mock subscription consumer
    MockSubscriptionConsumer internal SUBSCRIPTION;

    /// @notice Mock subscription consumer w/ Allowlist
    MockAllowlistSubscriptionConsumer internal ALLOWLIST_SUBSCRIPTION;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // Create mock protocol wallet
        uint256 initialNonce = vm.getNonce(address(this));
        address mockProtocolWalletAddress = vm.computeCreateAddress(address(this), initialNonce + 6);

        // Initialize contracts
        (Registry registry, EIP712Coordinator coordinator, Inbox inbox,,,) =
            LibDeploy.deployContracts(initialNonce, mockProtocolWalletAddress, MOCK_PROTOCOL_FEE);

        // Initialize mock protocol wallet
        PROTOCOL = new MockProtocol(registry);

        // Assign to internal (overriding EIP712Coordinator -> isolated Coordinator for tests)
        COORDINATOR = Coordinator(coordinator);
        INBOX = inbox;

        // Initalize mock nodes
        ALICE = new MockNode(registry);
        BOB = new MockNode(registry);
        CHARLIE = new MockNode(registry);

        // Initialize mock callback consumer
        CALLBACK = new MockCallbackConsumer(address(registry));

        // Initialize mock subscription consumer
        SUBSCRIPTION = new MockSubscriptionConsumer(address(registry));

        // Initialize mock subscription consumer w/ Allowlist
        // Add only Alice as initially allowed node
        address[] memory initialAllowed = new address[](1);
        initialAllowed[0] = address(ALICE);
        ALLOWLIST_SUBSCRIPTION = new MockAllowlistSubscriptionConsumer(address(registry), initialAllowed);
    }
}

/// @title CoordinatorGeneralTest
/// @notice General coordinator tests
contract CoordinatorGeneralTest is CoordinatorTest {
    /// @notice Cannot be reassigned a subscription ID
    function testCannotBeReassignedSubscriptionID() public {
        // Create new callback subscription
        uint32 id = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );
        assertEq(id, 1);

        // Create new subscriptions
        CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );
        CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );
        CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Assert head
        assertEq(COORDINATOR.id(), 5);

        // Delete subscriptions
        vm.startPrank(address(CALLBACK));
        COORDINATOR.cancelSubscription(1);
        COORDINATOR.cancelSubscription(3);

        // Assert head
        assertEq(COORDINATOR.id(), 5);

        // Create new subscription
        id = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );
        assertEq(id, 5);
        assertEq(COORDINATOR.id(), 6);
    }

    /// @notice Cannot receive response from non-coordinator contract
    function testCannotReceiveResponseFromNonCoordinator() public {
        // Expect revert sending from address(this)
        vm.expectRevert(BaseConsumer.NotCoordinator.selector);
        CALLBACK.rawReceiveCompute(1, 1, 1, address(this), MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, bytes32(0), 0);
    }
}

/// @title CoordinatorCallbackTest
/// @notice Coordinator tests specific to usage by CallbackConsumer
contract CoordinatorCallbackTest is CoordinatorTest {
    /// @notice Can create callback (one-time subscription)
    function testCanCreateCallback() public {
        vm.warp(0);

        // Get expected subscription ID
        uint32 expected = COORDINATOR.id();

        // Create new callback
        vm.expectEmit(address(COORDINATOR));
        emit SubscriptionCreated(expected);
        uint32 actual = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Assert subscription ID is correctly stored
        assertEq(expected, actual);

        // Assert subscription data is correctly stored
        Subscription memory sub = COORDINATOR.getSubscription(actual);
        assertEq(sub.activeAt, 0);
        assertEq(sub.owner, address(CALLBACK));
        assertEq(sub.redundancy, 1);
        assertEq(sub.frequency, 1);
        assertEq(sub.period, 0);
        assertEq(sub.containerId, HASHED_MOCK_CONTAINER_ID);
        assertEq(sub.lazy, false);

        // Assert subscription inputs are correctly stord
        assertEq(CALLBACK.getContainerInputs(actual, 0, 0, address(0)), MOCK_CONTAINER_INPUTS);
    }

    /// @notice Cannot deliver callback response if incorrect interval
    function testFuzzCannotDeliverCallbackIfIncorrectInterval(uint32 interval) public {
        // Check non-correct intervals
        vm.assume(interval != 1);

        // Create new callback request
        uint32 subId = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Attempt to deliver callback request w/ incorrect interval
        vm.expectRevert(Coordinator.IntervalMismatch.selector);
        ALICE.deliverCompute(subId, interval, "", "", "", NO_WALLET);
    }

    /// @notice Can deliver callback response successfully
    function testCanDeliverCallbackResponse() public {
        // Create new callback request
        uint32 subId = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver callback request
        vm.expectEmit(address(COORDINATOR));
        emit SubscriptionFulfilled(subId, address(ALICE));
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Assert delivery
        DeliveredOutput memory out = CALLBACK.getDeliveredOutput(subId, 1, 1);
        assertEq(out.subscriptionId, subId);
        assertEq(out.interval, 1);
        assertEq(out.redundancy, 1);
        assertEq(out.node, address(ALICE));
        assertEq(out.input, MOCK_INPUT);
        assertEq(out.output, MOCK_OUTPUT);
        assertEq(out.proof, MOCK_PROOF);
        assertEq(out.containerId, bytes32(0));
        assertEq(out.index, 0);
    }

    /// @notice Can deliver callback response once, across two unique nodes
    function testCanDeliverCallbackResponseOnceAcrossTwoNodes() public {
        // Create new callback request w/ redundancy = 2
        uint16 redundancy = 2;
        uint32 subId = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, redundancy, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver callback request from two nodes
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
        BOB.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Assert delivery
        address[2] memory nodes = [address(ALICE), address(BOB)];
        for (uint16 r = 1; r <= 2; r++) {
            DeliveredOutput memory out = CALLBACK.getDeliveredOutput(subId, 1, r);
            assertEq(out.subscriptionId, subId);
            assertEq(out.interval, 1);
            assertEq(out.redundancy, r);
            assertEq(out.node, nodes[r - 1]);
            assertEq(out.input, MOCK_INPUT);
            assertEq(out.output, MOCK_OUTPUT);
            assertEq(out.proof, MOCK_PROOF);
            assertEq(out.containerId, bytes32(0));
            assertEq(out.index, 0);
        }
    }

    /// @notice Cannot deliver callback response twice from same node
    function testCannotDeliverCallbackResponseFromSameNodeTwice() public {
        // Create new callback request w/ redundancy = 2
        uint16 redundancy = 2;
        uint32 subId = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, redundancy, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver callback request from Alice twice
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
        vm.expectRevert(Coordinator.NodeRespondedAlready.selector);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Delivered callbacks are not stored in Inbox
    function testCallbackDeliveryDoesNotStoreDataInInbox() public {
        // Create new callback request
        uint32 subId = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver callback request from Alice
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Expect revert (indexOOBError but in external contract)
        vm.expectRevert();
        INBOX.read(HASHED_MOCK_CONTAINER_ID, address(ALICE), 0);
    }
}

/// @title CoordinatorSubscriptionTest
/// @notice Coordinator tests specific to usage by SubscriptionConsumer
contract CoordinatorSubscriptionTest is CoordinatorTest {
    /// @notice Can read container inputs
    function testCanReadContainerInputs() public {
        bytes memory expected = SUBSCRIPTION.CONTAINER_INPUTS();
        bytes memory actual = SUBSCRIPTION.getContainerInputs(0, 0, 0, address(this));
        assertEq(expected, actual);
    }

    /// @notice Can cancel a subscription
    function testCanCancelSubscription() public {
        // Create subscription
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 3, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Cancel subscription and expect event emission
        vm.expectEmit(address(COORDINATOR));
        emit SubscriptionCancelled(subId);
        SUBSCRIPTION.cancelMockSubscription(subId);
    }

    /// @notice Can cancel a subscription that has been fulfilled at least once
    function testCanCancelFulfilledSubscription() public {
        // Create subscription
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 3, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Fulfill at least once
        vm.warp(60);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Cancel subscription
        SUBSCRIPTION.cancelMockSubscription(subId);
    }

    /// @notice Cannot cancel a subscription that does not exist
    function testCannotCancelNonExistentSubscription() public {
        // Try to delete subscription without creating
        vm.expectRevert(Coordinator.NotSubscriptionOwner.selector);
        SUBSCRIPTION.cancelMockSubscription(1);
    }

    /// @notice Cannot cancel a subscription that has already been cancelled
    function testCannotCancelCancelledSubscription() public {
        // Create and cancel subscription
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 3, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );
        SUBSCRIPTION.cancelMockSubscription(subId);

        // Attempt to cancel subscription again
        vm.expectRevert(Coordinator.NotSubscriptionOwner.selector);
        SUBSCRIPTION.cancelMockSubscription(subId);
    }

    /// @notice Cannot cancel a subscription you do not own
    function testCannotCancelUnownedSubscription() public {
        // Create callback subscription
        uint32 subId = CALLBACK.createMockRequest(
            MOCK_CONTAINER_ID, MOCK_CONTAINER_INPUTS, 1, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Attempt to cancel subscription from SUBSCRIPTION consumer
        vm.expectRevert(Coordinator.NotSubscriptionOwner.selector);
        SUBSCRIPTION.cancelMockSubscription(subId);
    }

    /// @notice Subscription intervals are properly calculated
    function testFuzzSubscriptionIntervalsAreCorrect(uint32 blockTime, uint32 frequency, uint32 period) public {
        // In the interest of testing time, upper bounding frequency loops + having at minimum 1 frequency
        vm.assume(frequency > 1 && frequency < 32);
        // Prevent upperbound overflow
        vm.assume(uint256(blockTime) + (uint256(frequency) * uint256(period)) < 2 ** 32 - 1);

        // Subscription activeAt timestamp
        uint32 activeAt = blockTime + period;

        // If period == 0, interval is always 1
        if (period == 0) {
            uint32 actual = COORDINATOR.getSubscriptionInterval(activeAt, period);
            assertEq(1, actual);
            return;
        }

        // Else, verify each manual interval
        // blockTime -> blockTime + period = underflow (this should never be called since we verify block.timestamp >= activeAt)
        // blockTime + N * period = N
        uint32 expected = 1;
        for (uint32 start = blockTime + period; start < (blockTime) + (frequency * period); start += period) {
            // Set current time
            vm.warp(start);

            // Check subscription interval
            uint32 actual = COORDINATOR.getSubscriptionInterval(activeAt, period);
            assertEq(expected, actual);

            // Check subscription interval 1s before if not first iteration
            if (expected != 1) {
                vm.warp(start - 1);
                actual = COORDINATOR.getSubscriptionInterval(activeAt, period);
                assertEq(expected - 1, actual);
            }

            // Increment expected for next cycle
            expected++;
        }
    }

    /// @notice Cannot deliver response for subscription that does not exist
    function testCannotDeliverResponseForNonExistentSubscription() public {
        // Attempt to deliver output for subscription without creating
        vm.expectRevert(Coordinator.SubscriptionNotFound.selector);
        ALICE.deliverCompute(1, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response for non-active subscription
    function testCannotDeliverResponseNonActiveSubscription() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 3, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Expect subscription to be inactive till time = 60
        vm.expectRevert(Coordinator.SubscriptionNotActive.selector);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Ensure subscription can be fulfilled when active
        // Force failure at next conditional (gas price)
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response for completed subscription
    function testCannotDeliverResponseForCompletedSubscription() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            1,
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Expect failure at any time prior to t = 60s
        vm.warp(1 minutes - 1);
        vm.expectRevert(Coordinator.SubscriptionNotActive.selector);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Deliver first response at time t = 60s
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Deliver second response at time t = 120s
        vm.warp(2 minutes);
        ALICE.deliverCompute(subId, 2, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Expect revert because interval > frequency
        vm.warp(3 minutes);
        vm.expectRevert(Coordinator.SubscriptionCompleted.selector);
        ALICE.deliverCompute(subId, 3, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response if incorrect interval
    function testCannotDeliverResponseIncorrectInterval() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            1,
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Successfully deliver at t = 60s, interval = 1
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Unsuccesfully deliver at t = 120s, interval = 1 (expected = 2)
        vm.warp(2 minutes);
        vm.expectRevert(Coordinator.IntervalMismatch.selector);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response delayed (after interval passed)
    function testCannotDeliverResponseDelayed() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            1,
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Attempt to deliver interval = 1 at time = 120s
        vm.warp(2 minutes);
        vm.expectRevert(Coordinator.IntervalMismatch.selector);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response early (before interval arrived)
    function testCannotDeliverResponseEarly() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            1,
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Attempt to deliver interval = 2 at time < 120s
        vm.warp(2 minutes - 1);
        vm.expectRevert(Coordinator.IntervalMismatch.selector);
        ALICE.deliverCompute(subId, 2, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response if redundancy maxxed out
    function testCannotDeliverMaxRedundancyResponse() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            2, // redundancy = 2
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Deliver from Alice
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Deliver from Bob
        BOB.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Attempt to deliver from Charlie, expect failure
        vm.expectRevert(Coordinator.IntervalCompleted.selector);
        CHARLIE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Cannot deliver response if already delivered in current interval
    function testCannotDeliverResponseIfAlreadyDeliveredInCurrentInterval() public {
        // Create new subscription at time = 0
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            2, // redundancy = 2
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Deliver from Alice
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Attempt to deliver from Alice again
        vm.expectRevert(Coordinator.NodeRespondedAlready.selector);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }
}

/// @title CoordinatorEagerSubscriptionTest
/// @notice Coordinator tests specific to usage by SubscriptionConsumer w/ eager fulfillment
contract CoordinatorEagerSubscriptionTest is CoordinatorTest {
    /// @notice Eager subscription delivery does not store outputs in inbox
    function testEagerSubscriptionDeliveryDoesNotStoreOutputsInInbox() public {
        // Create new eager subscription
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID,
            2, // frequency = 2
            1 minutes,
            2, // redundancy = 2
            false,
            NO_PAYMENT_TOKEN,
            0,
            NO_WALLET,
            NO_PROVER
        );

        // Fulfill subscription as Alice
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Verify exact rawReceiveCompute inputs
        DeliveredOutput memory out = SUBSCRIPTION.getDeliveredOutput(subId, 1, 1);
        assertEq(out.subscriptionId, subId);
        assertEq(out.interval, 1);
        assertEq(out.redundancy, 1);
        assertEq(out.node, address(ALICE));
        assertEq(out.input, MOCK_INPUT);
        assertEq(out.output, MOCK_OUTPUT);
        assertEq(out.proof, MOCK_PROOF);
        assertEq(out.containerId, bytes32(0));
        assertEq(out.index, 0);

        // Expect revert (indexOOBError but in external contract)
        vm.expectRevert();
        INBOX.read(HASHED_MOCK_CONTAINER_ID, address(ALICE), 0);
    }
}

/// @title CoordinatorLazySubscriptionTest
/// @notice Coordinator tests specific to usage by SubscriptionConsumer w/ lazy fulfillment
contract CoordinatorLazySubscriptionTest is CoordinatorTest {
    /// @notice Lazy subscription delivery stores outputs in inbox
    function testLazySubscriptionDeliveryStoresOutputsInInbox() public {
        // Create new lazy subscription
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 1, 1 minutes, 1, true, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver lazy subscription from Alice
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Verify exact rawReceiveCompute inputs
        DeliveredOutput memory out = SUBSCRIPTION.getDeliveredOutput(subId, 1, 1);
        assertEq(out.subscriptionId, subId);
        assertEq(out.interval, 1);
        assertEq(out.redundancy, 1);
        assertEq(out.node, address(ALICE));
        assertEq(out.input, "");
        assertEq(out.output, "");
        assertEq(out.proof, "");
        assertEq(out.containerId, HASHED_MOCK_CONTAINER_ID);
        assertEq(out.index, 0);

        // Verify data is stored in inbox
        InboxItem memory item = INBOX.read(HASHED_MOCK_CONTAINER_ID, address(ALICE), 0);
        assertEq(item.timestamp, 1 minutes);
        assertEq(item.subscriptionId, subId);
        assertEq(item.interval, 1);
        assertEq(item.input, MOCK_INPUT);
        assertEq(item.output, MOCK_OUTPUT);
        assertEq(item.proof, MOCK_PROOF);
    }

    /// @notice Can deliver lazy and eager subscription responses to same contract
    function testCanDeliverLazyAndEagerSubscriptionToSameContract() public {
        // Create new eager subscription
        vm.warp(0);
        uint32 subIdEager = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 1, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Create new lazy subscription
        uint32 subIdLazy = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 1, 1 minutes, 1, true, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver lazy and eager subscriptions
        vm.warp(1 minutes);
        ALICE.deliverCompute(subIdEager, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
        ALICE.deliverCompute(subIdLazy, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Verify eager rawReceiveCompute inputs
        DeliveredOutput memory out = SUBSCRIPTION.getDeliveredOutput(subIdEager, 1, 1);
        assertEq(out.subscriptionId, subIdEager);
        assertEq(out.interval, 1);
        assertEq(out.redundancy, 1);
        assertEq(out.node, address(ALICE));
        assertEq(out.input, MOCK_INPUT);
        assertEq(out.output, MOCK_OUTPUT);
        assertEq(out.proof, MOCK_PROOF);
        assertEq(out.containerId, bytes32(0));
        assertEq(out.index, 0);

        // Veirfy lazy rawReceiveCompute inputs
        out = SUBSCRIPTION.getDeliveredOutput(subIdLazy, 1, 1);
        assertEq(out.subscriptionId, subIdLazy);
        assertEq(out.interval, 1);
        assertEq(out.redundancy, 1);
        assertEq(out.node, address(ALICE));
        assertEq(out.input, "");
        assertEq(out.output, "");
        assertEq(out.proof, "");
        assertEq(out.containerId, HASHED_MOCK_CONTAINER_ID);
        assertEq(out.index, 0);

        // Ensure first index item in inbox is subIdLazy
        InboxItem memory item = INBOX.read(HASHED_MOCK_CONTAINER_ID, address(ALICE), 0);
        assertEq(item.timestamp, 1 minutes);
        assertEq(item.subscriptionId, subIdLazy);
        assertEq(item.interval, 1);
        assertEq(item.input, MOCK_INPUT);
        assertEq(item.output, MOCK_OUTPUT);
        assertEq(item.proof, MOCK_PROOF);
    }

    /// @notice Can delivery lazy subscriptions more than once
    function testCanDeliverLazySubscriptionsMoreThanOnce() public {
        // Create new lazy subscription w/ frequency = 2, redundancy = 2
        vm.warp(0);
        uint32 subId = SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 2, 1 minutes, 2, true, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver first interval from {Alice, Bob}
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
        BOB.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Deliver second interval from {Alice, Bob}
        vm.warp(2 minutes);
        ALICE.deliverCompute(subId, 2, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
        BOB.deliverCompute(subId, 2, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Verify inbox stores correct {timestamp, subscriptionId, interval}
        // Alice 0th-index (first interval response)
        InboxItem memory item = INBOX.read(HASHED_MOCK_CONTAINER_ID, address(ALICE), 0);
        assertEq(item.timestamp, 1 minutes);
        assertEq(item.subscriptionId, 1);
        assertEq(item.interval, 1);

        // Bob 0th-index (first interval response)
        item = INBOX.read(HASHED_MOCK_CONTAINER_ID, address(BOB), 0);
        assertEq(item.timestamp, 1 minutes);
        assertEq(item.subscriptionId, 1);
        assertEq(item.interval, 1);

        // Alice 1st-index (second interval response)
        item = INBOX.read(HASHED_MOCK_CONTAINER_ID, address(ALICE), 1);
        assertEq(item.timestamp, 2 minutes);
        assertEq(item.subscriptionId, 1);
        assertEq(item.interval, 2);

        // Bob 1st-index (second interval response)
        item = INBOX.read(HASHED_MOCK_CONTAINER_ID, address(BOB), 1);
        assertEq(item.timestamp, 2 minutes);
        assertEq(item.subscriptionId, 1);
        assertEq(item.interval, 2);
    }
}

/// @title CoordinatorAllowlistSubscriptionTest
/// @notice Coordinator tests specific to usage by SubscriptionConsumer w/ Allowlist
/// @dev We test Allowlist functionality via just a `SubscriptionConsumer` base (rather than redundantly testing a `CallbackConsumer` base too)
contract CoordinatorAllowlistSubscriptionTest is CoordinatorTest {
    /// @notice Initial allowlist is set correctly at contract creation
    function testInitialAllowlistCorrectlySet() public {
        // Ensure Alice is an allowed node
        assertTrue(ALLOWLIST_SUBSCRIPTION.isAllowedNode(address(ALICE)));

        // Ensure Bob and Charlie are not allowed nodes
        assertFalse(ALLOWLIST_SUBSCRIPTION.isAllowedNode(address(BOB)));
        assertFalse(ALLOWLIST_SUBSCRIPTION.isAllowedNode(address(CHARLIE)));
    }

    /// @notice Allowlist can be updated
    function testFuzzAllowlistCanBeUpdated(address[] memory nodes, bool[] memory statuses) public {
        // Bound array length to smallest of two fuzzed arrays
        uint256 arrayLen = nodes.length > statuses.length ? statuses.length : nodes.length;

        // Use fuzzed length to generated bounded nodes/statuses array
        address[] memory boundedNodes = new address[](arrayLen);
        bool[] memory boundedStatuses = new bool[](arrayLen);
        for (uint256 i = 0; i < arrayLen; i++) {
            boundedNodes[i] = nodes[i];
            boundedStatuses[i] = statuses[i];
        }

        // Unallow Alice to begin (default initialized)
        address[] memory removeAliceNodes = new address[](1);
        removeAliceNodes[0] = address(ALICE);
        bool[] memory removeAliceStatus = new bool[](1);
        removeAliceStatus[0] = false;
        ALLOWLIST_SUBSCRIPTION.updateMockAllowlist(removeAliceNodes, removeAliceStatus);

        // Ensure Alice is no longer an allowed node
        assertFalse(ALLOWLIST_SUBSCRIPTION.isAllowedNode(address(ALICE)));

        // Update Allowlist with bounded fuzzed arrays
        ALLOWLIST_SUBSCRIPTION.updateMockAllowlist(boundedNodes, boundedStatuses);

        // Ensure Allowlist is updated against fuzzed values
        for (uint256 i = 0; i < arrayLen; i++) {
            // Nested iteration since we may have duplicated status updates and want to select just the latest
            // E.g: [addr0, addr1, addr0], [true, false, false] — addr0 is duplicated but status is just the latest applied (false)
            bool lastStatus = boundedStatuses[i];
            // Reverse iterate for latest occurence up to current index
            for (uint256 j = arrayLen - 1; j >= i; j--) {
                if (boundedNodes[i] == boundedNodes[j]) {
                    lastStatus = boundedStatuses[j];
                    break;
                }
            }

            assertEq(ALLOWLIST_SUBSCRIPTION.isAllowedNode(boundedNodes[i]), lastStatus);
        }
    }

    /// @notice Delivering response from an allowed node succeeds
    function testCanDeliverResponseFromAllowedNode() public {
        // Create subscription
        vm.warp(0);
        uint32 subId = ALLOWLIST_SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 1, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Successfully fulfill from Alice
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Delivering response from an unallowed node fails
    function testFuzzCannotDeliverResponseFromUnallowedNode(address unallowedNode) public {
        // Ensure unallowed node is not Alice (default allowed at contract creation)
        vm.assume(unallowedNode != address(ALICE));

        // Create subscription
        vm.warp(0);
        uint32 subId = ALLOWLIST_SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 1, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Attempt to fulfill from an unallowed node
        vm.warp(1 minutes);
        vm.startPrank(unallowedNode);

        // Expect `NodeNotAllowed` revert
        vm.expectRevert(Allowlist.NodeNotAllowed.selector);
        COORDINATOR.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, payable(address(0)));
        vm.stopPrank();
    }

    /// @notice Delivering response from an allowed node across intervals succeeds
    function testCanDeliverResponseFromAllowedNodeAcrossIntervals() public {
        // Create subscription w/ frequency == 2
        vm.warp(0);
        uint32 subId = ALLOWLIST_SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 2, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Fulfill once from Alice
        vm.warp(1 minutes);
        ALICE.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Fulfill second time from Alice
        vm.warp(2 minutes);
        ALICE.deliverCompute(subId, 2, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
    }

    /// @notice Delivering response from an allowed node across intervals where the node is unallowed in some intervals fails
    function testCanDeliverResponseFromNodeInAllowedIntervalsOnly() public {
        // Setup statuses array
        bool[10] memory statuses = [false, true, false, false, true, true, true, false, false, true];

        // Create subscription w/ frequency 10
        vm.warp(0);
        uint32 subId = ALLOWLIST_SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 10, 1 minutes, 1, false, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Deliver response from Alice successfully or unsuccessfully depending on status in interval
        // Setup nodes array with just Alice (to correspond with each status update at each interval)
        address[] memory nodesArr = new address[](1);
        nodesArr[0] = address(ALICE);

        // For each (status, interval)-pair
        for (uint256 i = 0; i < statuses.length; i++) {
            // Setup delivery interval
            uint32 interval = uint32(i) + 1;

            // Warp to time of submission
            vm.warp(interval * 60);

            // Update Alice status according to statuses array
            bool newAliceStatus = statuses[i];
            bool[] memory statusArr = new bool[](1);
            statusArr[0] = newAliceStatus;
            ALLOWLIST_SUBSCRIPTION.updateMockAllowlist(nodesArr, statusArr);

            // Verify update is successful
            assertEq(ALLOWLIST_SUBSCRIPTION.isAllowedNode(address(ALICE)), newAliceStatus);

            // If status is unallowed, expect revert
            if (!newAliceStatus) {
                vm.expectRevert(Allowlist.NodeNotAllowed.selector);
            }
            ALICE.deliverCompute(subId, interval, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);
        }
    }

    /// @notice Delivering lazy subscription response from an unallowed node does not store authenticated `InboxItem` in `Inbox`
    function testInboxIsNotUpdatedOnUnallowedNodeFailedResponseDelivery() public {
        // Create subscription (w/ lazy = true)
        vm.warp(0);
        uint32 subId = ALLOWLIST_SUBSCRIPTION.createMockSubscription(
            MOCK_CONTAINER_ID, 1, 1 minutes, 1, true, NO_PAYMENT_TOKEN, 0, NO_WALLET, NO_PROVER
        );

        // Attempt to deliver from Bob expecting failure
        vm.warp(1 minutes);
        vm.expectRevert(Allowlist.NodeNotAllowed.selector);
        BOB.deliverCompute(subId, 1, MOCK_INPUT, MOCK_OUTPUT, MOCK_PROOF, NO_WALLET);

        // Ensure inbox item does not exist
        // Array out-of-bounds access since atomic tx execution previously failed
        vm.expectRevert();
        INBOX.read(HASHED_MOCK_CONTAINER_ID, address(BOB), 0);
    }
}
