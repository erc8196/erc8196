// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IERC8126} from "../../src/interfaces/IERC8126.sol";
import {IERC8004Validation} from "../../src/interfaces/IERC8004Validation.sol";
import {ERC8196Wallet} from "../../src/ERC8196Wallet.sol";

/// @notice Deterministic ERC-8126 verifier. `risk` is RISK polarity per ERC-8126
///         (Final): 0 = lowest risk, 100 = highest risk (higher = worse). This is the
///         raw scan score — no `100 - risk` inversion; the wallet rejects when it
///         exceeds the policy's minVerificationScore.
contract MockVerifier is IERC8126 {
    mapping(uint256 => uint8) public risk;

    function setRisk(uint256 agentId, uint8 riskScore) external {
        risk[agentId] = riskScore;
    }

    function getLatestRiskScore(uint256 agentId) external view returns (uint8) {
        return risk[agentId];
    }
}

/// @notice Functional ERC-8004 Validation Registry for tests. Stores responses keyed by
///         requestHash so `ValidationRegistryAdapter` can read them. (The wallet holds a
///         validation registry but does not call it on the scoring path.)
contract MockValidationRegistry is IERC8004Validation {
    struct Status {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
    }

    mapping(bytes32 => Status) private _status;

    function validationRequest(address validatorAddress, uint256 agentId, string calldata, bytes32 requestHash)
        external
    {
        Status storage s = _status[requestHash];
        s.validatorAddress = validatorAddress;
        s.agentId = agentId;
    }

    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata,
        bytes32 responseHash,
        string calldata tag
    ) external {
        Status storage s = _status[requestHash];
        s.response = response;
        s.responseHash = responseHash;
        s.tag = tag;
        s.lastUpdate = block.timestamp;
    }

    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (address, uint256, uint8, bytes32, string memory, uint256)
    {
        Status storage s = _status[requestHash];
        return (s.validatorAddress, s.agentId, s.response, s.responseHash, s.tag, s.lastUpdate);
    }

    function getSummary(uint256, address[] calldata, string calldata) external pure returns (uint64, uint8) {
        return (0, 0);
    }
}

/// @notice Records the last call it received. Accepts native value.
contract MockTarget {
    bytes public lastData;
    uint256 public lastValue;
    uint256 public callCount;

    receive() external payable {
        lastValue = msg.value;
        ++callCount;
    }

    fallback() external payable {
        lastData = msg.data;
        lastValue = msg.value;
        ++callCount;
    }
}

/// @notice Re-enters executeAction on receipt of value to prove the
///         ReentrancyGuard blocks nested execution.
contract ReentrantTarget {
    ERC8196Wallet public immutable wallet;

    constructor(ERC8196Wallet wallet_) {
        wallet = wallet_;
    }

    receive() external payable {
        // Args are irrelevant: nonReentrant reverts before they are read.
        wallet.executeAction(bytes32(0), address(0), 0, "", 0, bytes32(0), "");
    }
}
