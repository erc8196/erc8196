// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IERC8196} from "./interfaces/IERC8196.sol";
import {IERC8126} from "./interfaces/IERC8126.sol";
import {IERC8004Identity} from "./interfaces/IERC8004Identity.sol";
import {IERC8004Validation} from "./interfaces/IERC8004Validation.sol";
import {PolicyTypes} from "./libraries/PolicyTypes.sol";

/// @title ERC8196Wallet — reference implementation of the AI Agent Authenticated Wallet.
/// @notice Executes agent actions only when accompanied by (1) a valid EIP-712 agent
///         signature, (2) an active, in-window, within-limits policy, and (3) an
///         ERC-8126 risk score that does NOT exceed the policy threshold. Maintains a
///         hash-chained on-chain audit trail.
/// @dev    Implements the ERC-8196 interface verbatim. Three points are unspecified
///         by ERC-8196 and resolved here using ONLY spec-defined data (no added
///         parameters, policy fields, or features) — each is documented in NOTES.md:
///           1. `action` (in AGENT_ACTION_TYPEHASH) is not an executeAction param:
///              recovered by matching the signature against the policy's allowedActions.
///           2. ERC-8126 check mechanism: delegated to an IERC8126 verifier.
///           3. entropy reveal: ERC-8196 defines no reveal step; the commitment is
///              bound into the signed digest and the audit entry, nothing more.
contract ERC8196Wallet is IERC8196, EIP712, ReentrancyGuard {
    using PolicyTypes for PolicyTypes.Policy;

    /// @dev Defensive bound on policy list sizes (SCSVS S8.1.A). Caps the O(n) auth loop
    ///      in `_authenticate` and the registration loops. Owner-controlled; this only
    ///      rejects absurd input, it does not constrain any realistic policy.
    uint256 internal constant MAX_POLICY_ENTRIES = 100;

    /* ------------------------------------------------------------------ */
    /*                            EIP-712 TYPES                            */
    /* ------------------------------------------------------------------ */

    bytes32 internal constant AGENT_ACTION_TYPEHASH = keccak256(
        "AgentAction(address agent,string action,address target,uint256 value,"
        "bytes data,uint256 nonce,uint256 validUntil,bytes32 policyHash," "bytes32 entropyCommitment)"
    );

    bytes32 internal constant DELEGATION_TYPEHASH = keccak256(
        "Delegation(address delegator,address delegatee,bytes32 policyHash," "uint256 validUntil,uint256 nonce)"
    );

    /* ------------------------------------------------------------------ */
    /*                            DEPENDENCIES                             */
    /* ------------------------------------------------------------------ */

    /// @notice ERC-8004 Identity Registry — agents MUST be registered here first.
    IERC8004Identity public immutable identityRegistry;
    /// @notice ERC-8126 verifier — supplies the risk score capped by minVerificationScore.
    /// @dev    Owner-updatable (see setVerifier) so a deployment can migrate, e.g. from a
    ///         self-stored ScoreAnchor to the ERC-8004 ValidationRegistryAdapter once that
    ///         registry is live. The owner is already fully trusted (it can withdraw), so
    ///         an updatable verifier adds no new trust surface.
    IERC8126 public verifier;
    /// @notice ERC-8004 Validation Registry — target for optional audit-root anchoring.
    IERC8004Validation public immutable validationRegistry;
    /// @notice Wallet funder/owner (the deployer). Single-tenant: may reclaim native funds.
    address public immutable owner;
    /// @notice Emergency stop. While true, executeAction is blocked (owner kill-switch for
    ///         agent-key compromise — stops all policies at once without per-policy revokes).
    bool public paused;

    /* ------------------------------------------------------------------ */
    /*                              STORAGE                                */
    /* ------------------------------------------------------------------ */

    mapping(bytes32 => PolicyTypes.Policy) private _policies;
    mapping(bytes32 => string[]) private _allowedActions;
    mapping(bytes32 => mapping(address => bool)) private _allowedContract;
    mapping(bytes32 => mapping(address => bool)) private _blockedContract;
    mapping(bytes32 => mapping(uint256 => bool)) private _nonceUsed;
    mapping(bytes32 => PolicyTypes.DailySpend) private _dailySpend;

    /// @dev agentId resolved at registration (needed to key ERC-8126/8004 lookups,
    ///      which are keyed by agentId rather than address).
    mapping(bytes32 => uint256) private _policyAgentId;

    /// @dev per-owner salt so two identical policies hash distinctly.
    mapping(address => uint256) private _registrationNonce;

    // --- audit chain (sessionId == policyHash; see NOTES.md) ---
    mapping(bytes32 => bytes32) private _lastAuditHash;
    mapping(bytes32 => uint256) private _auditSequence;

    constructor(address identityRegistry_, address verifier_, address validationRegistry_)
        EIP712("ERC8196Wallet", "1")
    {
        identityRegistry = IERC8004Identity(identityRegistry_);
        verifier = IERC8126(verifier_);
        validationRegistry = IERC8004Validation(validationRegistry_);
        owner = msg.sender;
    }

    /* ------------------------------------------------------------------ */
    /*                          registerPolicy                            */
    /* ------------------------------------------------------------------ */

    /// @inheritdoc IERC8196
    function registerPolicy(
        address agent,
        string[] calldata allowedActions,
        address[] calldata allowedContracts,
        address[] calldata blockedContracts,
        uint256 maxValuePerTx,
        uint256 maxValuePerDay,
        uint256 validAfter,
        uint256 validUntil,
        uint8 minVerificationScore
    ) external returns (bytes32 policyHash) {
        // ERC-8126 risk scores are keyed by ERC-8004 agentId, so resolve it here for the gate.
        // Registration is NOT separately required (per ERC-8196): an unregistered agent has no
        // ERC-8126 score and is fail-closed (blocked) at execution — 8004 enforced via 8126.
        uint256 agentId = identityRegistry.agentIdOf(agent);

        if (validUntil <= block.timestamp || validUntil <= validAfter) {
            revert PolicyViolation(bytes32(0), "invalid validity window");
        }

        // SCSVS S8.1.A: bound the per-policy lists so the execution-time auth loop and
        // the registration loops cannot be made arbitrarily expensive.
        if (
            allowedActions.length > MAX_POLICY_ENTRIES || allowedContracts.length > MAX_POLICY_ENTRIES
                || blockedContracts.length > MAX_POLICY_ENTRIES
        ) {
            revert PolicyViolation(bytes32(0), "policy list too large");
        }

        // SCSVS S7.1.A1: one-time guard so the daily-spend accumulator (uint192) can never
        // overflow its cast. Far above any real cap; costs nothing per transaction.
        if (maxValuePerDay > type(uint192).max) {
            revert PolicyViolation(bytes32(0), "maxValuePerDay too large");
        }

        uint256 salt = _registrationNonce[msg.sender]++;
        policyHash = keccak256(
            abi.encode(
                msg.sender,
                agent,
                keccak256(abi.encode(allowedActions)),
                keccak256(abi.encode(allowedContracts)),
                keccak256(abi.encode(blockedContracts)),
                maxValuePerTx,
                maxValuePerDay,
                validAfter,
                validUntil,
                minVerificationScore,
                salt
            )
        );

        PolicyTypes.Policy storage p = _policies[policyHash];
        p.agentAddress = agent;
        p.ownerAddress = msg.sender;
        p.maxValuePerTx = maxValuePerTx;
        p.maxValuePerDay = maxValuePerDay;
        p.validAfter = validAfter;
        p.validUntil = validUntil;
        p.minVerificationScore = minVerificationScore;
        p.isActive = true;

        _policyAgentId[policyHash] = agentId;

        for (uint256 i; i < allowedActions.length; ++i) {
            _allowedActions[policyHash].push(allowedActions[i]);
        }
        for (uint256 i; i < allowedContracts.length; ++i) {
            _allowedContract[policyHash][allowedContracts[i]] = true;
        }
        for (uint256 i; i < blockedContracts.length; ++i) {
            _blockedContract[policyHash][blockedContracts[i]] = true;
        }

        emit PolicyRegistered(policyHash, msg.sender, agent, validUntil);
    }

    /* ------------------------------------------------------------------ */
    /*                           executeAction                            */
    /* ------------------------------------------------------------------ */

    /// @inheritdoc IERC8196
    function executeAction(
        bytes32 policyHash,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes32 entropyCommitment,
        bytes calldata signature
    ) external nonReentrant returns (bool success, bytes32 auditEntryId) {
        if (paused) revert WalletPaused();
        PolicyTypes.Policy storage p = _policies[policyHash];
        if (!p.isActive) revert PolicyViolation(policyHash, "inactive policy");

        // --- temporal validity ---
        if (block.timestamp < p.validAfter || block.timestamp > p.validUntil) {
            revert PolicyExpired(policyHash, p.validUntil);
        }

        // --- target whitelist / blacklist (deny-by-default whitelist) ---
        if (_blockedContract[policyHash][target]) revert PolicyViolation(policyHash, "target blocked");
        if (!_allowedContract[policyHash][target]) revert PolicyViolation(policyHash, "target not allowed");

        // --- value limits ---
        if (value > p.maxValuePerTx) revert ValueExceedsLimit(value, p.maxValuePerTx);
        _accrueDailySpend(policyHash, p.maxValuePerDay, value);

        // --- replay protection ---
        if (_nonceUsed[policyHash][nonce]) revert PolicyViolation(policyHash, "nonce used");
        _nonceUsed[policyHash][nonce] = true;

        // --- ERC-8126 verification gate ---
        // ERC-8126 (Final) score is RISK: higher = worse. ERC-8196 rejects when it
        // EXCEEDS the policy's minVerificationScore (the maximum tolerated risk). No
        // inversion — the risk score is consumed directly.
        uint8 riskScore = verifier.getLatestRiskScore(_policyAgentId[policyHash]);
        if (riskScore > p.minVerificationScore) {
            revert PolicyViolation(policyHash, "risk score exceeds threshold");
        }

        // --- signature: recover the action and authenticate the agent ---
        string memory action =
            _authenticate(p.agentAddress, policyHash, p, target, value, data, nonce, entropyCommitment, signature);

        // --- execute ---
        (success,) = target.call{value: value}(data);
        if (!success) revert PolicyViolation(policyHash, "call failed");

        // --- audit ---
        auditEntryId = _appendAudit(policyHash, action, target, value, entropyCommitment);

        emit ActionExecuted(policyHash, p.agentAddress, target, value, auditEntryId);
    }

    /// @dev Recovers which allowedActions entry was signed and verifies the agent's
    ///      signature against AGENT_ACTION_TYPEHASH. ERC-8196 omits `action` from the
    ///      executeAction parameters; we recover it by trying each allowedActions
    ///      candidate (small list) — this simultaneously enforces action ∈ allowedActions.
    ///      `validUntil` in the typehash is sourced from the policy (also absent as a param).
    function _authenticate(
        address agent,
        bytes32 policyHash,
        PolicyTypes.Policy storage p,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes32 entropyCommitment,
        bytes calldata signature
    ) internal view returns (string memory action) {
        bytes32 dataHash = keccak256(data);
        string[] storage actions = _allowedActions[policyHash];
        for (uint256 i; i < actions.length; ++i) {
            bytes32 digest = _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        AGENT_ACTION_TYPEHASH,
                        agent,
                        keccak256(bytes(actions[i])),
                        target,
                        value,
                        dataHash,
                        nonce,
                        p.validUntil,
                        policyHash,
                        entropyCommitment
                    )
                )
            );
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signature);
            if (err == ECDSA.RecoverError.NoError && recovered == agent) {
                return actions[i];
            }
        }
        revert InvalidSignature(address(0), agent);
    }

    /* ------------------------------------------------------------------ */
    /*                           revokePolicy                             */
    /* ------------------------------------------------------------------ */

    /// @inheritdoc IERC8196
    function revokePolicy(bytes32 policyHash, string calldata reason) external {
        PolicyTypes.Policy storage p = _policies[policyHash];
        if (msg.sender != p.ownerAddress) revert PolicyViolation(policyHash, "not owner");
        if (!p.isActive) revert PolicyViolation(policyHash, "already inactive");
        p.isActive = false;
        emit PolicyRevoked(policyHash, reason);
    }

    /* ------------------------------------------------------------------ */
    /*                             getPolicy                              */
    /* ------------------------------------------------------------------ */

    /// @inheritdoc IERC8196
    function getPolicy(bytes32 policyHash)
        external
        view
        returns (address agent, address policyOwner, uint256 maxValuePerTx, uint256 validUntil, bool isActive)
    {
        PolicyTypes.Policy storage p = _policies[policyHash];
        return (p.agentAddress, p.ownerAddress, p.maxValuePerTx, p.validUntil, p.isActive);
    }

    /* ------------------------------------------------------------------ */
    /*                              INTERNAL                               */
    /* ------------------------------------------------------------------ */

    /// @dev Enforces the optional daily cap using UTC calendar-day buckets.
    ///      `maxValuePerDay == 0` means unset/unlimited (per PolicyTypes).
    function _accrueDailySpend(bytes32 policyHash, uint256 maxValuePerDay, uint256 value) internal {
        if (maxValuePerDay == 0) return;
        uint64 today = uint64(block.timestamp / 1 days);
        PolicyTypes.DailySpend storage d = _dailySpend[policyHash];
        uint256 spent = d.day == today ? d.spent : 0;
        spent += value;
        if (spent > maxValuePerDay) revert ValueExceedsLimit(value, maxValuePerDay);
        d.day = today;
        d.spent = uint192(spent);
    }

    /// @dev Appends a hash-chained audit entry. ERC-8196: "Each audit entry MUST
    ///      include `previousHash` for integrity." sessionId is the policyHash.
    function _appendAudit(
        bytes32 sessionId,
        string memory actionType,
        address target,
        uint256 value,
        bytes32 entropyCommitment
    ) internal returns (bytes32 entryId) {
        bytes32 previousHash = _lastAuditHash[sessionId];
        uint256 sequence = _auditSequence[sessionId];
        entryId = keccak256(
            abi.encode(previousHash, sequence, sessionId, actionType, target, value, entropyCommitment, block.timestamp)
        );
        _lastAuditHash[sessionId] = entryId;
        _auditSequence[sessionId] = sequence + 1;
        emit AuditEntryLogged(entryId, sequence, sessionId, actionType);
    }

    /* ------------------------------------------------------------------ */
    /*                       owner administration                         */
    /* ------------------------------------------------------------------ */

    /// @notice Emitted when the owner reclaims native funds.
    event Withdrawal(address indexed to, uint256 amount);
    /// @notice Emitted when the owner migrates the ERC-8126 verifier.
    event VerifierUpdated(address indexed previousVerifier, address indexed newVerifier);
    /// @notice Emitted when the owner toggles the emergency stop.
    event PausedSet(bool paused);

    error NotOwner();
    error WithdrawFailed();
    error WalletPaused();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Single-tenant fund recovery (SCSVS S9.1.A1): the owner (deployer/funder)
    ///         may withdraw native value so funds can't be locked if the agent key is lost.
    /// @dev    NOT a bypass of agent gating — the gates constrain the AGENT, not the owner,
    ///         who already owns these funds. `nonReentrant` for defence in depth.
    function withdraw(address to, uint256 amount) external nonReentrant onlyOwner {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
        emit Withdrawal(to, amount);
    }

    /// @notice Migrate the ERC-8126 verifier (e.g. ScoreAnchor -> ValidationRegistryAdapter).
    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        emit VerifierUpdated(address(verifier), newVerifier);
        verifier = IERC8126(newVerifier);
    }

    /// @notice Emergency stop / resume for executeAction (owner kill-switch).
    function setPaused(bool paused_) external onlyOwner {
        paused = paused_;
        emit PausedSet(paused_);
    }

    /// @notice Required to receive native value for funding outbound calls.
    receive() external payable {}
}
