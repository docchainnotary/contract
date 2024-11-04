#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, BytesN, Env,
    Symbol, Vec, vec, Map, String, panic_with_error, log, 
    xdr::{ScErrorType, ScErrorCode},
};

mod types;
use types::*;

#[contract]
pub struct NotaryContract;

#[contractimpl]
impl NotaryContract {
    /// Initialize the contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), NotaryError> {
        if env.storage().instance().has(&ADMIN) {
            return Err(NotaryError::AlreadyExists);
        }

        let state = NotaryState {
            admin: admin.clone(),
            documents: Map::new(&env),
            user_documents: Map::new(&env),
            authorities: Vec::new(&env),
            claims: Map::new(&env),
            settings: Map::new(&env),
        };

        env.storage().instance().set(&STATE, &state);
        env.storage().instance().set(&ADMIN, &admin);

        Ok(())
    }

    /// Create a new document
    pub fn create_document(
        env: Env,
        hash: BytesN<32>,
        title: String,
        signers: Vec<Address>,
        metadata: Map<Symbol, String>,
    ) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        if state.documents.contains_key(hash.clone()) {
            return Err(NotaryError::AlreadyExists);
        }

        // Create initial version with zero-filled parent hash
        let version = DocumentVersion {
            hash: hash.clone(),
            parent_hash: BytesN::from_array(&env, &[0; 32]), // Zero-filled bytes for no parent
            title: title.clone(),
            status: VersionStatus::PendingApproval,
            creator: env.current_contract_address(),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            signatures: Vec::new(&env),
            required_signers: signers.clone(),
            metadata: metadata.clone(),
        };

        let document = Document {
            hash: hash.clone(),
            status: DocumentStatus::Pending,
            owner: env.current_contract_address(),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            current_version: 0,
            versions: vec![&env, version],
            authorized_signers: signers,
            metadata,
        };

        state.documents.set(hash.clone(), document);

        let mut user_docs = state.user_documents.get(env.current_contract_address())
            .unwrap_or(Vec::new(&env));
        user_docs.push_back(hash.clone());
        state.user_documents.set(env.current_contract_address(), user_docs);

        env.storage().instance().set(&STATE, &state);
        env.events().publish((DOCS,), NotaryEvent::DocumentCreated(hash));

        Ok(())
    }

    /// Helper: Check if address is authorized for document
    fn is_authorized(document: Document, address: Address) -> bool {
        address == document.owner || document.authorized_signers.contains(&address)
    }

    /// Add new version to document
    pub fn add_version(
        env: Env,
        document_hash: BytesN<32>,
        version_hash: BytesN<32>,
        title: String,
        metadata: Map<Symbol, String>,
    ) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        let mut document = state.documents.get(document_hash.clone())
            .ok_or(NotaryError::NotFound)?;

        if !Self::is_authorized(document.clone(), env.current_contract_address()) {
            return Err(NotaryError::Unauthorized);
        }

        let version = DocumentVersion {
            hash: version_hash.clone(),
            parent_hash: document_hash.clone(),
            title,
            status: VersionStatus::Draft,
            creator: env.current_contract_address(),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            signatures: Vec::new(&env),
            required_signers: document.authorized_signers.clone(),
            metadata,
        };

        document.versions.push_back(version);
        document.current_version = (document.versions.len() - 1) as u32;
        document.updated_at = env.ledger().timestamp();

        state.documents.set(document_hash.clone(), document);
        env.storage().instance().set(&STATE, &state);

        env.events().publish((DOCS,), NotaryEvent::VersionAdded(version_hash));

        Ok(())
    }

    /// Sign a document version
    pub fn sign_document(
        env: Env,
        document_hash: BytesN<32>,
        signature: Signature,
    ) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        let mut document = state.documents.get(document_hash.clone())
            .ok_or(NotaryError::NotFound)?;

        if !document.authorized_signers.contains(&env.current_contract_address()) {
            return Err(NotaryError::Unauthorized);
        }

        let current_version_idx = document.current_version as usize;
        let mut current_version = document.versions.get(current_version_idx as u32).unwrap().clone();

        if current_version.signatures.iter().any(|s| s.signer == signature.signer) {
            return Err(NotaryError::AlreadyExists);
        }

        current_version.signatures.push_back(signature);
        current_version.updated_at = env.ledger().timestamp();

        if current_version.signatures.len() == current_version.required_signers.len() {
            current_version.status = VersionStatus::Approved;
            document.status = DocumentStatus::Active;
        }

        document.versions.set(current_version_idx as u32, current_version);
        document.updated_at = env.ledger().timestamp();

        state.documents.set(document_hash.clone(), document);
        env.storage().instance().set(&STATE, &state);

        env.events().publish((DOCS,), NotaryEvent::DocumentSigned(document_hash));

        Ok(())
    }

    /// Register a certification authority
    pub fn register_authority(env: Env, authority: Address) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        if env.current_contract_address() != state.admin {
            return Err(NotaryError::Unauthorized);
        }

        if !state.authorities.contains(&authority) {
            state.authorities.push_back(authority.clone());
            env.storage().instance().set(&STATE, &state);
            env.events().publish((AUTH,), NotaryEvent::AuthorityAdded(authority));
        }

        Ok(())
    }

    /// Add identity claim
    pub fn add_claim(
        env: Env,
        user: Address,
        claim: IdentityClaim,
    ) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        if !state.authorities.contains(&env.current_contract_address()) {
            return Err(NotaryError::InvalidAuthority);
        }

        if claim.expires_at <= env.ledger().timestamp() {
            return Err(NotaryError::ExpiredClaim);
        }

        let mut user_claims = state.claims.get(user.clone())
            .unwrap_or(Vec::new(&env));
        user_claims.push_back(claim);
        state.claims.set(user.clone(), user_claims);

        env.storage().instance().set(&STATE, &state);
        env.events().publish((AUTH,), NotaryEvent::ClaimAdded(user));

        Ok(())
    }

    /// Verify document
    pub fn verify_document(env: Env, document_hash: BytesN<32>) -> Result<Document, NotaryError> {
        let state: NotaryState = env.storage().instance().get(&STATE).unwrap();
        
        state.documents.get(document_hash)
            .ok_or(NotaryError::NotFound)
    }

    /// Get user's documents
    pub fn get_user_documents(env: Env, user: Address) -> Result<Vec<BytesN<32>>, NotaryError> {
        let state: NotaryState = env.storage().instance().get(&STATE).unwrap();
        
        Ok(state.user_documents.get(user)
            .unwrap_or(Vec::new(&env)).clone())
    }

    /// Update document status
    pub fn update_status(
        env: Env,
        document_hash: BytesN<32>,
        new_status: DocumentStatus,
    ) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        let mut document = state.documents.get(document_hash.clone())
            .ok_or(NotaryError::NotFound)?;

        if env.current_contract_address() != document.owner {
            return Err(NotaryError::Unauthorized);
        }

        document.status = new_status.clone();
        document.updated_at = env.ledger().timestamp();

        state.documents.set(document_hash.clone(), document);
        env.storage().instance().set(&STATE, &state);

        env.events().publish((DOCS,), NotaryEvent::StatusChanged(document_hash, new_status));

        Ok(())
    }

    /// Get contract configuration
    pub fn get_config(env: Env, key: Symbol) -> Result<String, NotaryError> {
        let state: NotaryState = env.storage().instance().get(&STATE).unwrap();
        
        state.settings.get(key)
            .ok_or(NotaryError::NotFound)
    }

    /// Update contract configuration
    pub fn update_config(
        env: Env,
        key: Symbol,
        value: String,
    ) -> Result<(), NotaryError> {
        let mut state: NotaryState = env.storage().instance().get(&STATE).unwrap();

        if env.current_contract_address() != state.admin {
            return Err(NotaryError::Unauthorized);
        }

        state.settings.set(key, value);
        env.storage().instance().set(&STATE, &state);

        Ok(())
    }
}
