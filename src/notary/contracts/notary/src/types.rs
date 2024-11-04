use soroban_sdk::{
    contracttype, symbol_short, Address, BytesN, Symbol, Vec, Map, String,
    xdr::{ScErrorType, ScErrorCode},
};

/// Storage identifiers (max 9 chars)
pub const ADMIN: Symbol = symbol_short!("ADMIN");
pub const STATE: Symbol = symbol_short!("STATE");
pub const DOCS: Symbol = symbol_short!("DOCS");
pub const AUTH: Symbol = symbol_short!("AUTH");

/// Configuration keys (max 9 chars)
pub const MAX_SIGN: Symbol = symbol_short!("MAX_SIGN");
pub const MIN_SIGN: Symbol = symbol_short!("MIN_SIGN");
pub const EXP_DAYS: Symbol = symbol_short!("EXP_DAYS");
pub const FEE_AMT: Symbol = symbol_short!("FEE_AMT");
pub const VER_REQ: Symbol = symbol_short!("VER_REQ");

/// Error codes for the contract
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum NotaryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidVersion = 4,
    InvalidStatus = 5,
    InvalidSignature = 6,
    ExpiredClaim = 7,
    MissingIdentityClaim = 8,
    InvalidAuthority = 9,
    InvalidInput = 10,
    InvalidState = 11,
    OperationFailed = 12,
}

impl From<soroban_sdk::Error> for NotaryError {
    fn from(_error: soroban_sdk::Error) -> Self {
        NotaryError::OperationFailed
    }
}

impl From<NotaryError> for soroban_sdk::Error {
    fn from(error: NotaryError) -> Self {
        let (type_, code) = match error {
            NotaryError::AlreadyExists => (ScErrorType::Contract, ScErrorCode::ExistingValue),
            NotaryError::NotFound => (ScErrorType::Contract, ScErrorCode::MissingValue),
            NotaryError::Unauthorized => (ScErrorType::Contract, ScErrorCode::InternalError),
            _ => (ScErrorType::Contract, ScErrorCode::InternalError),
        };
        soroban_sdk::Error::from_type_and_code(type_, code)
    }
}

/// Document status
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum DocumentStatus {
    Pending,
    Active,
    Revoked,
    Expired,
}

/// Version status
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum VersionStatus {
    Draft,
    PendingApproval,
    Approved,
    Rejected,
    Superseded,
}

/// Identity claim structure
#[derive(Clone, Debug)]
#[contracttype]
pub struct IdentityClaim {
    pub authority: Address,
    pub claim_type: Symbol,
    pub claim_value: BytesN<32>,
    pub signature: BytesN<64>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub metadata: Map<Symbol, String>,
}

/// Signature structure
#[derive(Clone, Debug)]
#[contracttype]
pub struct Signature {
    pub signer: Address,
    pub timestamp: u64,
    pub signature_data: BytesN<64>,
    pub claim_reference: BytesN<32>,
}

/// Document version structure with fixed parent hash handling
#[derive(Clone, Debug)]
#[contracttype]
pub struct DocumentVersion {
    pub hash: BytesN<32>,
    pub parent_hash: BytesN<32>,
    pub title: String,
    pub status: VersionStatus,
    pub creator: Address,
    pub created_at: u64,
    pub updated_at: u64,
    pub signatures: Vec<Signature>,
    pub required_signers: Vec<Address>,
    pub metadata: Map<Symbol, String>,
}

/// Document structure
#[derive(Clone, Debug)]
#[contracttype]
pub struct Document {
    pub hash: BytesN<32>,
    pub status: DocumentStatus,
    pub owner: Address,
    pub created_at: u64,
    pub updated_at: u64,
    pub current_version: u32,
    pub versions: Vec<DocumentVersion>,
    pub authorized_signers: Vec<Address>,
    pub metadata: Map<Symbol, String>,
}

/// Contract storage structure
#[derive(Clone, Debug)]
#[contracttype]
pub struct NotaryState {
    pub admin: Address,
    pub documents: Map<BytesN<32>, Document>,
    pub user_documents: Map<Address, Vec<BytesN<32>>>,
    pub authorities: Vec<Address>,
    pub claims: Map<Address, Vec<IdentityClaim>>,
    pub settings: Map<Symbol, String>,
}

/// Event types for logging
#[contracttype]
pub enum NotaryEvent {
    DocumentCreated(BytesN<32>),
    VersionAdded(BytesN<32>),
    DocumentSigned(BytesN<32>),
    StatusChanged(BytesN<32>, DocumentStatus),
    ClaimAdded(Address),
    AuthorityAdded(Address),
}

impl From<&NotaryError> for soroban_sdk::Error {
    fn from(error: &NotaryError) -> Self {
        match error {
            NotaryError::AlreadyExists => soroban_sdk::Error::from_type_and_code(ScErrorType::Contract, ScErrorCode::ExistingValue),
            NotaryError::NotFound => soroban_sdk::Error::from_type_and_code(ScErrorType::Contract, ScErrorCode::MissingValue),
            NotaryError::Unauthorized => soroban_sdk::Error::from_type_and_code(ScErrorType::Contract, ScErrorCode::InternalError),
            _ => soroban_sdk::Error::from_type_and_code(ScErrorType::Contract, ScErrorCode::InternalError),
        }
    }
}

