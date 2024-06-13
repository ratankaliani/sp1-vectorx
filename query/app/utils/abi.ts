import { AbiEvent } from 'abitype';

export const VECTORX_ABI = [
    {
        "type": "function",
        "name": "DEFAULT_ADMIN_ROLE",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "GUARDIAN_ROLE",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "TIMELOCK_ROLE",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "VERSION",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "string",
                "internalType": "string"
            }
        ],
        "stateMutability": "pure"
    },
    {
        "type": "function",
        "name": "authoritySetIdToHash",
        "inputs": [
            {
                "name": "",
                "type": "uint64",
                "internalType": "uint64"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "blockHeightToHeaderHash",
        "inputs": [
            {
                "name": "",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "commitHeaderRange",
        "inputs": [
            {
                "name": "_authoritySetId",
                "type": "uint64",
                "internalType": "uint64"
            },
            {
                "name": "_targetBlock",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "dataRootCommitments",
        "inputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "frozen",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "gateway",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "address",
                "internalType": "address"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "getRoleAdmin",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "grantRole",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "account",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "hasRole",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "account",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "headerRangeCommitmentTreeSize",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "headerRangeFunctionId",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "initialize",
        "inputs": [
            {
                "name": "_params",
                "type": "tuple",
                "internalType": "struct VectorX.InitParameters",
                "components": [
                    {
                        "name": "guardian",
                        "type": "address",
                        "internalType": "address"
                    },
                    {
                        "name": "gateway",
                        "type": "address",
                        "internalType": "address"
                    },
                    {
                        "name": "height",
                        "type": "uint32",
                        "internalType": "uint32"
                    },
                    {
                        "name": "header",
                        "type": "bytes32",
                        "internalType": "bytes32"
                    },
                    {
                        "name": "authoritySetId",
                        "type": "uint64",
                        "internalType": "uint64"
                    },
                    {
                        "name": "authoritySetHash",
                        "type": "bytes32",
                        "internalType": "bytes32"
                    },
                    {
                        "name": "headerRangeFunctionId",
                        "type": "bytes32",
                        "internalType": "bytes32"
                    },
                    {
                        "name": "rotateFunctionId",
                        "type": "bytes32",
                        "internalType": "bytes32"
                    },
                    {
                        "name": "headerRangeCommitmentTreeSize",
                        "type": "uint32",
                        "internalType": "uint32"
                    }
                ]
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "latestAuthoritySetId",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "uint64",
                "internalType": "uint64"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "latestBlock",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "proxiableUUID",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "rangeStartBlocks",
        "inputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "renounceRole",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "account",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "requestHeaderRange",
        "inputs": [
            {
                "name": "_authoritySetId",
                "type": "uint64",
                "internalType": "uint64"
            },
            {
                "name": "_requestedBlock",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "outputs": [],
        "stateMutability": "payable"
    },
    {
        "type": "function",
        "name": "requestRotate",
        "inputs": [
            {
                "name": "_currentAuthoritySetId",
                "type": "uint64",
                "internalType": "uint64"
            }
        ],
        "outputs": [],
        "stateMutability": "payable"
    },
    {
        "type": "function",
        "name": "revokeRole",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "account",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "rotate",
        "inputs": [
            {
                "name": "_currentAuthoritySetId",
                "type": "uint64",
                "internalType": "uint64"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "rotateFunctionId",
        "inputs": [],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "stateRootCommitments",
        "inputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "supportsInterface",
        "inputs": [
            {
                "name": "interfaceId",
                "type": "bytes4",
                "internalType": "bytes4"
            }
        ],
        "outputs": [
            {
                "name": "",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "updateBlockRangeData",
        "inputs": [
            {
                "name": "_startBlocks",
                "type": "uint32[]",
                "internalType": "uint32[]"
            },
            {
                "name": "_endBlocks",
                "type": "uint32[]",
                "internalType": "uint32[]"
            },
            {
                "name": "_headerHashes",
                "type": "bytes32[]",
                "internalType": "bytes32[]"
            },
            {
                "name": "_dataRootCommitments",
                "type": "bytes32[]",
                "internalType": "bytes32[]"
            },
            {
                "name": "_stateRootCommitments",
                "type": "bytes32[]",
                "internalType": "bytes32[]"
            },
            {
                "name": "_endAuthoritySetId",
                "type": "uint64",
                "internalType": "uint64"
            },
            {
                "name": "_endAuthoritySetHash",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "updateFreeze",
        "inputs": [
            {
                "name": "_freeze",
                "type": "bool",
                "internalType": "bool"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "updateFunctionIds",
        "inputs": [
            {
                "name": "_headerRangeFunctionId",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "_rotateFunctionId",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "_headerRangeCommitmentTreeSize",
                "type": "uint32",
                "internalType": "uint32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "updateGateway",
        "inputs": [
            {
                "name": "_gateway",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "updateGenesisState",
        "inputs": [
            {
                "name": "_height",
                "type": "uint32",
                "internalType": "uint32"
            },
            {
                "name": "_header",
                "type": "bytes32",
                "internalType": "bytes32"
            },
            {
                "name": "_authoritySetId",
                "type": "uint64",
                "internalType": "uint64"
            },
            {
                "name": "_authoritySetHash",
                "type": "bytes32",
                "internalType": "bytes32"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "upgradeTo",
        "inputs": [
            {
                "name": "newImplementation",
                "type": "address",
                "internalType": "address"
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "upgradeToAndCall",
        "inputs": [
            {
                "name": "newImplementation",
                "type": "address",
                "internalType": "address"
            },
            {
                "name": "data",
                "type": "bytes",
                "internalType": "bytes"
            }
        ],
        "outputs": [],
        "stateMutability": "payable"
    },
    {
        "type": "event",
        "name": "AdminChanged",
        "inputs": [
            {
                "name": "previousAdmin",
                "type": "address",
                "indexed": false,
                "internalType": "address"
            },
            {
                "name": "newAdmin",
                "type": "address",
                "indexed": false,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "AuthoritySetStored",
        "inputs": [
            {
                "name": "authoritySetId",
                "type": "uint64",
                "indexed": false,
                "internalType": "uint64"
            },
            {
                "name": "authoritySetHash",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "BeaconUpgraded",
        "inputs": [
            {
                "name": "beacon",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "HeadUpdate",
        "inputs": [
            {
                "name": "blockNumber",
                "type": "uint32",
                "indexed": false,
                "internalType": "uint32"
            },
            {
                "name": "headerHash",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "HeaderRangeCommitmentStored",
        "inputs": [
            {
                "name": "startBlock",
                "type": "uint32",
                "indexed": false,
                "internalType": "uint32"
            },
            {
                "name": "endBlock",
                "type": "uint32",
                "indexed": false,
                "internalType": "uint32"
            },
            {
                "name": "dataCommitment",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            },
            {
                "name": "stateCommitment",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            },
            {
                "name": "headerRangeCommitmentTreeSize",
                "type": "uint32",
                "indexed": false,
                "internalType": "uint32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "HeaderRangeRequested",
        "inputs": [
            {
                "name": "trustedBlock",
                "type": "uint32",
                "indexed": false,
                "internalType": "uint32"
            },
            {
                "name": "trustedHeader",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            },
            {
                "name": "authoritySetId",
                "type": "uint64",
                "indexed": false,
                "internalType": "uint64"
            },
            {
                "name": "authoritySetHash",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            },
            {
                "name": "targetBlock",
                "type": "uint32",
                "indexed": false,
                "internalType": "uint32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "Initialized",
        "inputs": [
            {
                "name": "version",
                "type": "uint8",
                "indexed": false,
                "internalType": "uint8"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "RoleAdminChanged",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "previousAdminRole",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "newAdminRole",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "RoleGranted",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "account",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "sender",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "RoleRevoked",
        "inputs": [
            {
                "name": "role",
                "type": "bytes32",
                "indexed": true,
                "internalType": "bytes32"
            },
            {
                "name": "account",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            },
            {
                "name": "sender",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "RotateRequested",
        "inputs": [
            {
                "name": "currentAuthoritySetId",
                "type": "uint64",
                "indexed": false,
                "internalType": "uint64"
            },
            {
                "name": "currentAuthoritySetHash",
                "type": "bytes32",
                "indexed": false,
                "internalType": "bytes32"
            }
        ],
        "anonymous": false
    },
    {
        "type": "event",
        "name": "Upgraded",
        "inputs": [
            {
                "name": "implementation",
                "type": "address",
                "indexed": true,
                "internalType": "address"
            }
        ],
        "anonymous": false
    },
    {
        "type": "error",
        "name": "AuthoritySetNotFound",
        "inputs": []
    },
    {
        "type": "error",
        "name": "ContractFrozen",
        "inputs": []
    },
    {
        "type": "error",
        "name": "NextAuthoritySetExists",
        "inputs": []
    },
    {
        "type": "error",
        "name": "OldAuthoritySetId",
        "inputs": []
    },
    {
        "type": "error",
        "name": "OnlyGuardian",
        "inputs": [
            {
                "name": "sender",
                "type": "address",
                "internalType": "address"
            }
        ]
    },
    {
        "type": "error",
        "name": "OnlyTimelock",
        "inputs": [
            {
                "name": "sender",
                "type": "address",
                "internalType": "address"
            }
        ]
    },
    {
        "type": "error",
        "name": "TrustedHeaderNotFound",
        "inputs": []
    }
];

export const VECTORX_INITIALIZED_EVENT = {
    "type": "event",
    "name": "Initialized",
    "inputs": [
        {
            "name": "version",
            "type": "uint8",
            "indexed": false,
            "internalType": "uint8"
        }
    ],
    "anonymous": false
} as AbiEvent;

export const VECTORX_HEAD_UPDATE_EVENT = {
    anonymous: false,
    inputs: [
        {
            indexed: false,
            internalType: 'uint32',
            name: 'blockNumber',
            type: 'uint32'
        },
        {
            indexed: false,
            internalType: 'bytes32',
            name: 'headerHash',
            type: 'bytes32'
        }
    ],
    name: 'HeadUpdate',
    type: 'event'
} as AbiEvent;

export const VECTORX_DATA_COMMITMENT_EVENT = {
    "type": "event",
    "name": "HeaderRangeCommitmentStored",
    "inputs": [
        {
            "name": "startBlock",
            "type": "uint32",
            "indexed": false,
            "internalType": "uint32"
        },
        {
            "name": "endBlock",
            "type": "uint32",
            "indexed": false,
            "internalType": "uint32"
        },
        {
            "name": "dataCommitment",
            "type": "bytes32",
            "indexed": false,
            "internalType": "bytes32"
        },
        {
            "name": "stateCommitment",
            "type": "bytes32",
            "indexed": false,
            "internalType": "bytes32"
        },
        {
            "name": "headerRangeCommitmentTreeSize",
            "type": "uint32",
            "indexed": false,
            "internalType": "uint32"
        }
    ],
    "anonymous": false
} as AbiEvent;
