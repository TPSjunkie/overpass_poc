use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use wasm_bindgen::prelude::*;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpCode {
    Add {
        cell: Vec<u8>,
    },
    Remove {
        cell: Vec<u8>,
    },
    Update {
        cell: Vec<u8>,
    },
    SetCode {
        code: Vec<u8>,
        new_code: Vec<u8>,
        new_data: Vec<u8>,
        new_libraries: Vec<u8>,
        new_version: u32,
    },
    SetData {
        cell: Vec<u8>,
        new_data: Vec<u8>,
    },
    SetLibraries {
        cell: Vec<u8>,
        new_libraries: Vec<u8>,
    },
    SetVersion {
        cell: Vec<u8>,
        new_version: u32,
    },
    Deploy {
        code: Vec<u8>,
        initial_state: Vec<u8>,
    },
    Call {
        contract_id: u32,
        function: Vec<u8>,
        args: Vec<u8>,
    },
    UpdateState {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    AddReference {
        from: u32,
        to: u32,
    },
    RemoveReference {
        from: u32,
        to: u32,
    },
    SetRoot {
        index: u32,
    },
    Intermediate(IntermediateOpCode),
    Wallet(WalletOpCode),
    Channel(ChannelOpCode),
    Custom(u8),
    Transaction {
        data: Vec<u8>,
    },
}
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContractOpCode {
    CreatePayment = 0xA0,
    UpdateState = 0xA1,
    FinalizeState = 0xA2,
    DisputeState = 0xA3,
    InitChannel = 0xA4,
}

impl From<ContractOpCode> for u8 {
    fn from(code: ContractOpCode) -> Self {
        code as u8
    }
}
impl OpCode {
    #[inline]
    pub fn to_u8(&self) -> u8 {
        match self {
            OpCode::Add { .. } => 0x01,
            OpCode::Remove { .. } => 0x02,
            OpCode::Update { .. } => 0x03,
            OpCode::SetCode { .. } => 0x04,
            OpCode::SetData { .. } => 0x05,
            OpCode::SetLibraries { .. } => 0x06,
            OpCode::SetVersion { .. } => 0x07,
            OpCode::Deploy { .. } => 0x01,
            OpCode::Call { .. } => 0x02,
            OpCode::UpdateState { .. } => 0x03,
            OpCode::AddReference { .. } => 0x04,
            OpCode::RemoveReference { .. } => 0x05,
            OpCode::SetRoot { .. } => 0x06,
            OpCode::Intermediate(op) => u8::from(*op),
            OpCode::Wallet(op) => u8::from(*op),
            OpCode::Channel(op) => u8::from(*op),
            OpCode::Custom(op) => *op,
            OpCode::Transaction { .. } => 0xC0,
        }
    }

    pub fn from_u8(value: u8) -> Option<OpCode> {
        match value {
            0x01 => Some(OpCode::Deploy {
                code: Vec::new(),
                initial_state: Vec::new(),
            }),
            0x02 => Some(OpCode::Call {
                contract_id: 0,
                function: Vec::new(),
                args: Vec::new(),
            }),
            0x03 => Some(OpCode::UpdateState {
                key: Vec::new(),
                value: Vec::new(),
            }),
            0x04 => Some(OpCode::AddReference { from: 0, to: 0 }),
            0x05 => Some(OpCode::RemoveReference { from: 0, to: 0 }),
            0xC0 => Some(OpCode::Transaction { data: Vec::new() }),
            _ => {
                if let Ok(op) = IntermediateOpCode::try_from(value) {
                    return Some(OpCode::Intermediate(op));
                }
                if let Ok(op) = WalletOpCode::try_from(value) {
                    return Some(OpCode::Wallet(op));
                }
                if let Ok(op) = ChannelOpCode::try_from(value) {
                    return Some(OpCode::Channel(op));
                }
                Some(OpCode::Custom(value))
            }
        }
    }
}

pub trait Operation {
    fn op_code(&self) -> OpCode;
    fn validate(&self) -> bool;
    fn execute(&self) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub op_code: OpCode,
    pub message: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChannelOpCode {
    CreatePayment = 0xA0,
    UpdateState = 0xA1,
    FinalizeState = 0xA2,
    DisputeState = 0xA3,
    InitChannel = 0xA4,
    Update = 0xA5,
    Finalize = 0xA6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WalletOpCode {
    CreateChannel = 0x70,
    UpdateChannel = 0x71,
    CloseChannel = 0x72,
    UpdateWalletState = 0x90,
    CreateTransaction = 0xC0,
    ProcessTransaction = 0xC2,
    Create = 0x73,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IntermediateOpCode {
    RequestChannelOpen = 0x20,
    RequestChannelClose = 0x22,
    RequestManualRebalance = 0x24,
    RegisterWallet = 0x30,
    UpdateWalletRoot = 0x31,
    StoreWalletState = 0x43,
}

impl From<ChannelOpCode> for u8 {
    fn from(code: ChannelOpCode) -> Self {
        code as u8
    }
}

impl From<WalletOpCode> for u8 {
    fn from(code: WalletOpCode) -> Self {
        code as u8
    }
}

impl From<IntermediateOpCode> for u8 {
    fn from(code: IntermediateOpCode) -> Self {
        code as u8
    }
}

impl TryFrom<u8> for OpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01..=0x05 => Ok(OpCode::from_u8(value).unwrap()),
            _ => {
                if let Ok(op) = ChannelOpCode::try_from(value) {
                    return Ok(OpCode::Channel(op));
                }
                if let Ok(op) = WalletOpCode::try_from(value) {
                    return Ok(OpCode::Wallet(op));
                }
                if let Ok(op) = IntermediateOpCode::try_from(value) {
                    return Ok(OpCode::Intermediate(op));
                }
                Ok(OpCode::Custom(value))
            }
        }
    }
}

impl TryFrom<u8> for ChannelOpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xA0 => Ok(Self::CreatePayment),
            0xA1 => Ok(Self::UpdateState),
            0xA2 => Ok(Self::FinalizeState),
            0xA3 => Ok(Self::DisputeState),
            0xA4 => Ok(Self::InitChannel),
            0xA5 => Ok(Self::Update),
            0xA6 => Ok(Self::Finalize),
            _ => Err("Invalid Channel operation code"),
        }
    }
}

impl TryFrom<u8> for WalletOpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x70 => Ok(Self::CreateChannel),
            0x71 => Ok(Self::UpdateChannel),
            0x72 => Ok(Self::CloseChannel),
            0x73 => Ok(Self::Create),
            0x90 => Ok(Self::UpdateWalletState),
            0xC0 => Ok(Self::CreateTransaction),
            0xC2 => Ok(Self::ProcessTransaction),
            _ => Err("Invalid Wallet operation code"),
        }
    }
}

impl TryFrom<u8> for IntermediateOpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x20 => Ok(Self::RequestChannelOpen),
            0x22 => Ok(Self::RequestChannelClose),
            0x24 => Ok(Self::RequestManualRebalance),
            0x30 => Ok(Self::RegisterWallet),
            0x31 => Ok(Self::UpdateWalletRoot),
            0x43 => Ok(Self::StoreWalletState),
            _ => Err("Invalid Intermediate operation code"),
        }
    }
}