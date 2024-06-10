// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IVectorX} from "./interfaces/IVectorX.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @notice VectorX is a light client for Avail's consensus.
/// @dev The light client tracks both the state of Avail's Grandpa consensus and Vector, Avail's
///     data commitment solution.
/// @dev Ensure that all new storage variables are placed after existing storage variables to avoid
/// storage corruption during upgrades.
contract VectorX is IVectorX, TimelockedUpgradeable {
    /// @notice Indicator of if the contract is frozen.
    bool public frozen;

    /// @notice The latest block that has been committed.
    uint32 public latestBlock;

    /// @notice The latest authority set id used in commitHeaderRange.
    uint64 public latestAuthoritySetId;

    /// @notice Maps block height to the header hash of the block.
    mapping(uint32 => bytes32) public blockHeightToHeaderHash;

    /// @notice Maps authority set id to the authority set hash.
    mapping(uint64 => bytes32) public authoritySetIdToHash;

    /// @notice Maps block ranges to data commitments. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public dataRootCommitments;

    /// @notice Maps block ranges to state commitments. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public stateRootCommitments;

    /// @notice Maps range hashes to the start block of the range. This allows us
    ///     to know the block height of an attestation.
    mapping(bytes32 => uint32) public rangeStartBlocks;

    /// @notice The commitment tree size for the header range.
    uint32 public headerRangeCommitmentTreeSize;

    struct InitParameters {
        address guardian;
        uint32 height;
        bytes32 header;
        uint64 authoritySetId;
        bytes32 authoritySetHash;
        uint32 headerRangeCommitmentTreeSize;
        bytes32 vectorXProgramVkey;
        address verifier;
    }

    /// @notice The verification key for the VectorX program.
    bytes32 public vectorXProgramVkey;

    /// @notice The deployed SP1 verifier contract.
    ISP1Verifier public verifier;

    /// @notice The type of proof that is being verified.
    enum ProofType {HeaderRangeProof, RotateProof}

    function VERSION() external pure override returns (string memory) {
        return "1.0.0";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters for the contract.
    function initialize(InitParameters calldata _params) external initializer {
        blockHeightToHeaderHash[_params.height] = _params.header;
        authoritySetIdToHash[_params.authoritySetId] = _params.authoritySetHash;
        latestAuthoritySetId = _params.authoritySetId;
        latestBlock = _params.height;
        vectorXProgramVkey = _params.vectorXProgramVkey;
        verifier = ISP1Verifier(_params.verifier);

        headerRangeCommitmentTreeSize = _params.headerRangeCommitmentTreeSize;

        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);
    }

    /// @notice Update the freeze parameter.
    function updateFreeze(bool _freeze) external onlyGuardian {
        frozen = _freeze;
    }

    /// @notice Update the commitment tree size for the header range function.
    function updateCommitmentTreeSize(
        uint32 _headerRangeCommitmentTreeSize
    ) external onlyGuardian {
        headerRangeCommitmentTreeSize = _headerRangeCommitmentTreeSize;
    }


    /// @notice Update the genesis state of the light client.
    function updateGenesisState(uint32 _height, bytes32 _header, uint64 _authoritySetId, bytes32 _authoritySetHash)
        external
        onlyGuardian
    {
        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;

        authoritySetIdToHash[_authoritySetId] = _authoritySetHash;
        latestAuthoritySetId = _authoritySetId;
    }

    /// @notice Force update the data & state commitments for a range of blocks.
    function updateBlockRangeData(
        uint32[] calldata _startBlocks,
        uint32[] calldata _endBlocks,
        bytes32[] calldata _headerHashes,
        bytes32[] calldata _dataRootCommitments,
        bytes32[] calldata _stateRootCommitments,
        uint64 _endAuthoritySetId,
        bytes32 _endAuthoritySetHash
    ) external onlyGuardian {
        assert(
            _startBlocks.length > 0 && _startBlocks.length == _endBlocks.length
                && _endBlocks.length == _headerHashes.length && _headerHashes.length == _dataRootCommitments.length
                && _dataRootCommitments.length == _stateRootCommitments.length
        );
        require(_startBlocks[0] == latestBlock);
        for (uint256 i = 0; i < _startBlocks.length; i++) {
            if (i < _startBlocks.length - 1) {
                require(_endBlocks[i] == _startBlocks[i + 1]);
            }
            bytes32 key = keccak256(abi.encode(_startBlocks[i], _endBlocks[i]));
            dataRootCommitments[key] = _dataRootCommitments[i];
            stateRootCommitments[key] = _stateRootCommitments[i];
            rangeStartBlocks[key] = _startBlocks[i];

            blockHeightToHeaderHash[_endBlocks[i]] = _headerHashes[i];

            emit HeadUpdate(_endBlocks[i], _headerHashes[i]);

            emit HeaderRangeCommitmentStored(
                _startBlocks[i],
                _endBlocks[i],
                _dataRootCommitments[i],
                _stateRootCommitments[i],
                headerRangeCommitmentTreeSize
            );
        }
        latestBlock = _endBlocks[_endBlocks.length - 1];

        authoritySetIdToHash[_endAuthoritySetId] = _endAuthoritySetHash;
        latestAuthoritySetId = _endAuthoritySetId;
    }


    /// @notice Add target header hash, and data + state commitments for (latestBlock, targetBlock].
    /// @param _authoritySetId The authority set id of the header range (latestBlock, targetBlock].
    /// @param _targetBlock The block height of the target block.
    /// @dev The trusted block and requested block must have the same authority set id. If the target
    /// block is greater than the max batch size of the circuit, the proof will fail to generate.
    function commitHeaderRange(uint64 _authoritySetId, uint32 _targetBlock) external {
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        if (_authoritySetId < latestAuthoritySetId) {
            revert OldAuthoritySetId();
        }

        if (_authoritySetId > latestAuthoritySetId) {
            latestAuthoritySetId = _authoritySetId;
        }

        require(_targetBlock > latestBlock);

        bytes memory input =
            abi.encodePacked(latestBlock, trustedHeader, _authoritySetId, authoritySetHash, _targetBlock);

        // bytes memory output = ISuccinctGateway(gateway).verifiedCall(headerRangeFunctionId, input);

        (bytes32 targetHeaderHash, bytes32 stateRootCommitment, bytes32 dataRootCommitment) =
            abi.decode(output, (bytes32, bytes32, bytes32));

        blockHeightToHeaderHash[_targetBlock] = targetHeaderHash;

        // Store the data and state commitments for the range (latestBlock, targetBlock].
        bytes32 key = keccak256(abi.encode(latestBlock, _targetBlock));
        dataRootCommitments[key] = dataRootCommitment;
        stateRootCommitments[key] = stateRootCommitment;
        rangeStartBlocks[key] = latestBlock;

        emit HeadUpdate(_targetBlock, targetHeaderHash);

        emit HeaderRangeCommitmentStored(
            latestBlock, _targetBlock, dataRootCommitment, stateRootCommitment, headerRangeCommitmentTreeSize
        );

        // Update latest block.
        latestBlock = _targetBlock;
    }


    /// @notice Adds the authority set hash for the next authority set id.
    /// @param _currentAuthoritySetId The authority set id of the current authority set.
    function rotate(uint64 _currentAuthoritySetId, bytes calldata proof, bytes calldata publicValues) external {
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 currentAuthoritySetHash = authoritySetIdToHash[_currentAuthoritySetId];
        // Note: Occurs if requesting a new authority set id that is not the next authority set id.
        if (currentAuthoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        bytes32 nextAuthoritySetHash = authoritySetIdToHash[_currentAuthoritySetId + 1];
        if (nextAuthoritySetHash != bytes32(0)) {
            revert NextAuthoritySetExists();
        }

        (uint8 ProofTypeInt, bytes _, bytes32 newAuthoritySetHash) = abi.decode(publicValues, (uint8, bytes, bytes32));
        ProofType proofType = ProofType(ProofTypeInt);

        if (proofType != ProofType.RotateProof) {
            revert InvalidProofType();
        }

        // Verify the proof with the associated public values. This will revert if proof invalid.
        verifier.verifyProof(vectorXProgramVkey, publicValues, proof);

        // Store the authority set hash for the next authority set id.
        authoritySetIdToHash[_currentAuthoritySetId + 1] = newAuthoritySetHash;

        emit AuthoritySetStored(_currentAuthoritySetId + 1, newAuthoritySetHash);
    }

    /// @notice Update the verification key hash if the SP1 program was updated.
    /// @param _vkey The verification key hash of the new SP1 program.
    function updateVkeyHash(bytes32 _vkey) external onlyGuardian {
        vectorXProgramVkey = _vkey;
    }
}
