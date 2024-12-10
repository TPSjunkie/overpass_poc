


// client_errors.rs

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;

/// Represents a result with a success value and an error value.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    SystemError(SystemError),
    ChannelError(ChannelError),
    ClientError(ClientError),
    ZkProofError(ZkProofError),
    StateBocError(StateBocError),
    CellError(CellError),
    CustomError(String),
    SerializationError(String),
    DeserializationError(String),
    NetworkError(String),
    IoError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SystemError(err) => write!(f, "System error: {}", err),
            Error::ChannelError(err) => write!(f, "Channel error: {}", err),
            Error::ClientError(err) => write!(f, "Client error: {}", err),
            Error::ZkProofError(err) => write!(f, "ZK proof error: {}", err),
            Error::StateBocError(err) => write!(f, "State BOC error: {}", err),
            Error::CellError(err) => write!(f, "Cell error: {}", err),
            Error::CustomError(msg) => write!(f, "Custom error: {}", msg),
            Error::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Error::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Error::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Error::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<SystemError> for Error {
    fn from(err: SystemError) -> Self {
        Error::SystemError(err)
    }
}

impl From<ChannelError> for Error {
    fn from(err: ChannelError) -> Self {
        Error::ChannelError(err)
    }
}

impl From<ClientError> for Error {
    fn from(err: ClientError) -> Self {
        Error::ClientError(err)
    }
}

impl From<CellError> for Error {
    fn from(err: CellError) -> Self {
        Error::CellError(err)
    }
}

impl From<ZkProofError> for Error {
    fn from(err: ZkProofError) -> Self {
        Error::ZkProofError(err)
    }
}

impl From<StateBocError> for Error {
    fn from(err: StateBocError) -> Self {
        Error::StateBocError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerializationError(err.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemErrorType {
    ProofGenerationError,
    CircuitError,
    InvalidTransaction,
    InvalidSignature,
    InvalidPublicKey,
    InvalidReference,
    SerializationFailed,
    InvalidAddress,
    SerializationError,
    DeserializationFailed,  
    InvalidHash,
    RpcError,
    NotImplemented,
    CryptoError,
    DecryptionError,
    ResourceLimitReached,
    PeerUpdateError,
    InvalidNonce,
    InvalidSequence,
    InvalidAmount,
    InvalidData,
    InvalidState,
    InvalidProof,
    NoProof,
    DataConversionError,
    InvalidInput,
    ProofError,
    StateDataMismatch,
    DeserializationError,
    OperationDisabled,
    ResourceUnavailable,
    RemoteError,
    VerificationError,
    StateUpdateError,
    LockAcquisitionError,
    NetworkError,
    NoRoots,
    InsufficientBalance,
    SpendingLimitExceeded,
    NoRootCell,
    InvalidOperation,
    NotFound,
    InsufficientCharge,
    StorageError,
}

impl fmt::Display for SystemErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            SystemErrorType::ProofGenerationError => "Proof generation error",
            SystemErrorType::CircuitError => "Circuit error",
            SystemErrorType::InvalidTransaction => "Invalid transaction",
            SystemErrorType::InvalidSignature => "Invalid signature",
            SystemErrorType::InvalidPublicKey => "Invalid public key",
            SystemErrorType::InvalidReference => "Invalid reference",
            SystemErrorType::InvalidAddress => "Invalid address",
            SystemErrorType::SerializationError => "Serialization error",
            SystemErrorType::InvalidHash => "Invalid hash",
            SystemErrorType::RpcError => "RPC error",
            SystemErrorType::CryptoError => "Crypto error",
            SystemErrorType::DecryptionError => "Decryption error",
            SystemErrorType::RemoteError => "Remote error",
            SystemErrorType::DeserializationFailed => "Deserialization failed",
            SystemErrorType::ResourceLimitReached => "Resource limit reached",
            SystemErrorType::PeerUpdateError => "Peer update error",
            SystemErrorType::DeserializationError => "Deserialization error",
            SystemErrorType::InvalidNonce => "Invalid nonce",
            SystemErrorType::NotImplemented => "Not implemented",
            SystemErrorType::InvalidSequence => "Invalid sequence",
            SystemErrorType::SerializationFailed => "Serialization failed",
            SystemErrorType::InvalidAmount => "Invalid amount",
            SystemErrorType::InvalidData => "Invalid data",
            SystemErrorType::InvalidState => "Invalid state",
            SystemErrorType::InvalidProof => "Invalid proof",
            SystemErrorType::NoProof => "No proof",
            SystemErrorType::DataConversionError => "Data conversion error",
            SystemErrorType::InvalidInput => "Invalid input",
            SystemErrorType::ProofError => "Proof error",
            SystemErrorType::StateDataMismatch => "State data mismatch",
            SystemErrorType::OperationDisabled => "Operation disabled",
            SystemErrorType::ResourceUnavailable => "Resource unavailable",
            SystemErrorType::VerificationError => "Verification error",
            SystemErrorType::StateUpdateError => "State update error",
            SystemErrorType::LockAcquisitionError => "Lock acquisition error",
            SystemErrorType::NetworkError => "Network error",
            SystemErrorType::NoRoots => "No roots",
            SystemErrorType::InsufficientBalance => "Insufficient balance",
            SystemErrorType::SpendingLimitExceeded => "Spending limit exceeded",
            SystemErrorType::NoRootCell => "No root cell",
            SystemErrorType::InvalidOperation => "Invalid operation",
            SystemErrorType::NotFound => "Not found",
            SystemErrorType::InsufficientCharge => "Insufficient charge",
            SystemErrorType::StorageError => "Storage error",
        };
        write!(f, "{}", error_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SystemError {
    pub error_type: SystemErrorType,
    pub message: String,
}

impl SystemError {
    pub fn new(error_type: SystemErrorType, message: String) -> Self {
        Self {
            error_type,
            message,
        }
    }

    pub fn error_type(&self) -> SystemErrorType {
        self.error_type
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_type, self.message)
    }
}

impl std::error::Error for SystemError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelErrorType {
    InvalidTransaction,
    InvalidNonce,
    InvalidSequence,
    InvalidAmount,
    InsufficientBalance,
    SpendingLimitExceeded,
    NoRootCell,
    InvalidOperation,
    InvalidArgument,
    NotFound,
    InvalidProof,
}

impl fmt::Display for ChannelErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            ChannelErrorType::InvalidTransaction => "Invalid transaction",
            ChannelErrorType::InvalidNonce => "Invalid nonce",
            ChannelErrorType::InvalidSequence => "Invalid sequence",
            ChannelErrorType::InvalidAmount => "Invalid amount",
            ChannelErrorType::InsufficientBalance => "Insufficient balance",
            ChannelErrorType::SpendingLimitExceeded => "Spending limit exceeded",
            ChannelErrorType::NoRootCell => "No root cell",
            ChannelErrorType::InvalidOperation => "Invalid operation",
            ChannelErrorType::InvalidArgument => "Invalid argument",
            ChannelErrorType::NotFound => "Not found",
            ChannelErrorType::InvalidProof => "Invalid proof",
        };
        write!(f, "{}", error_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelError {
    pub error_type: ChannelErrorType,
    pub message: String,
}

impl ChannelError {
    pub fn new(error_type: ChannelErrorType, message: String) -> Self {
        Self {
            error_type,
            message,
        }
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_type, self.message)
    }
}

impl std::error::Error for ChannelError {}

impl From<io::Error> for ChannelError {
    fn from(err: io::Error) -> Self {
        ChannelError::new(ChannelErrorType::InvalidOperation, err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientErrorType {
    InvalidProof,
    InvalidTransaction,
    InvalidNonce,
    InvalidSequence,
    InvalidAmount,
    InsufficientBalance,
    SpendingLimitExceeded,
    NoRootCell,
    InvalidOperation,
    InvalidArgument,
    NotFound,
}

impl fmt::Display for ClientErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            ClientErrorType::InvalidProof => "Invalid proof",
            ClientErrorType::InvalidTransaction => "Invalid transaction",
            ClientErrorType::InvalidNonce => "Invalid nonce",
            ClientErrorType::InvalidSequence => "Invalid sequence",
            ClientErrorType::InvalidAmount => "Invalid amount",
            ClientErrorType::InsufficientBalance => "Insufficient balance",
            ClientErrorType::SpendingLimitExceeded => "Spending limit exceeded",
            ClientErrorType::NoRootCell => "No root cell",
            ClientErrorType::InvalidOperation => "Invalid operation",
            ClientErrorType::InvalidArgument => "Invalid argument",
            ClientErrorType::NotFound => "Not found",
        };
        write!(f, "{}", error_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientError {
    pub error_type: ClientErrorType,
    pub message: String,
}

impl ClientError {
    pub fn new(error_type: ClientErrorType, message: String) -> Self {
        Self {
            error_type,
            message,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_type, self.message)
    }
}

impl std::error::Error for ClientError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellError {
    DataTooLarge,
    TooManyReferences,
    InvalidData,
    IoError(String),
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            CellError::DataTooLarge => "Cell data is too large",
            CellError::TooManyReferences => "Too many references in cell",
            CellError::InvalidData => "Invalid cell data",
            CellError::IoError(err) => return write!(f, "IO error: {}", err),
        };
        write!(f, "{}", error_str)
    }
}

impl std::error::Error for CellError {}

impl From<io::Error> for CellError {
    fn from(err: io::Error) -> Self {
        CellError::IoError(err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkProofError {
    InvalidProof,
    InvalidProofData,
    InvalidProofDataLength,
    InvalidProofDataFormat,
    InvalidProofDataSignature,
    InvalidProofDataPublicKey,
    InvalidProofDataHash,
}

impl fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            ZkProofError::InvalidProof => "Invalid proof",
            ZkProofError::InvalidProofData => "Invalid proof data",
            ZkProofError::InvalidProofDataLength => "Invalid proof data length",
            ZkProofError::InvalidProofDataFormat => "Invalid proof data format",
            ZkProofError::InvalidProofDataSignature => "Invalid proof data signature",
            ZkProofError::InvalidProofDataPublicKey => "Invalid proof data public key",
            ZkProofError::InvalidProofDataHash => "Invalid proof data hash",
        };
        write!(f, "{}", error_str)
    }
}

impl std::error::Error for ZkProofError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateBocError {
    TooManyCells,
    NoRoots,
    TotalSizeTooLarge,
    CellDataTooLarge,
    TooManyReferences,
    InvalidReference { from: usize, to: usize },
    InvalidRoot(usize),
    InvalidMerkleProof,
    InvalidPrunedBranch,
    SerializationError(String),
    DeserializationError(String),
    CycleDetected,
    MaxDepthExceeded,
}

impl fmt::Display for StateBocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            StateBocError::TooManyCells => "Too many cells",
            StateBocError::NoRoots => "No roots",
            StateBocError::TotalSizeTooLarge => "Total size too large",
            StateBocError::CellDataTooLarge => "Cell data too large",
            StateBocError::TooManyReferences => "Too many references",
            StateBocError::InvalidReference { from, to } => {
                return write!(f, "Invalid reference from {} to {}", from, to)
            }
            StateBocError::InvalidRoot(index) => return write!(f, "Invalid root at index {}", index),
            StateBocError::InvalidMerkleProof => "Invalid Merkle proof",
            StateBocError::InvalidPrunedBranch => "Invalid pruned branch",
            StateBocError::CycleDetected => "Cycle detected",
            StateBocError::MaxDepthExceeded => "Max depth exceeded",
            StateBocError::SerializationError(err) => return write!(f, "Serialization error: {}", err),
            StateBocError::DeserializationError(err) => {
                return write!(f, "Deserialization error: {}", err)
            }
        };
        write!(f, "{}", error_str)
    }
}


/// Global errors
#[derive(Debug)]
pub enum GlobalStateError {
    /// An error that can occur when serializing or deserializing data.
    SerializationError,

    /// An error that can occur when deserializing data.
    DeserializationError,

    /// An error that can occur when generating a proof.
    GlobalMerkleCircuitError,
}

impl From<GlobalStateError> for String {
    fn from(e: GlobalStateError) -> Self {
        match e {
            GlobalStateError::SerializationError => "Serialization error".to_string(),
            GlobalStateError::DeserializationError => "Deserialization error".to_string(),
            GlobalStateError::GlobalMerkleCircuitError => "Global Merkle circuit error".to_string(),
        }
    }
}   

impl fmt::Display for GlobalStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            GlobalStateError::SerializationError => "Serialization error",
            GlobalStateError::DeserializationError => "Deserialization error",
            GlobalStateError::GlobalMerkleCircuitError => "Global Merkle circuit error",
        };
        write!(f, "{}", error_str)
    }
}



impl std::error::Error for StateBocError {}
