#![cfg(test)]
use super::*;
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction},
    vec, map, Vec, Env,
};

mod test {
    use super::*;

    /// Helper function to setup contract testing environment
    fn setup() -> (Env, Address, NotaryContractClient<'static>) {
        let env = Env::default();
        let contract_id = env.register_contract(None, NotaryContract);
        let client = NotaryContractClient::new(&env, &contract_id);
        let admin = Address::random(&env);
        
        // Initialize contract
        client.initialize(admin.clone()).unwrap();
        
        (env, admin, client)
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register_contract(None, NotaryContract);
        let client = NotaryContractClient::new(&env, &contract_id);
        
        let admin = Address::random(&env);
        assert!(client.initialize(admin).is_ok());
    }

    #[test]
    fn test_initialize_already_exists() {
        let (env, admin, client) = setup();
        
        // Try to initialize again
        assert!(client.initialize(admin).is_err());
    }

    #[test]
    fn test_document_lifecycle() {
        let (env, _admin, client) = setup();

        // Create document
        let hash = BytesN::random(&env);
        let title = String::from_slice(&env, "Test Document");
        let signers = vec![&env, Address::random(&env)];
        let metadata = Map::new(&env);
        
        assert!(client.create_document(hash.clone(), title.clone(), signers.clone(), metadata.clone()).is_ok());

        // Test version creation
        let version_hash = BytesN::random(&env);
        let version_title = String::from_slice(&env, "Version 2");
        assert!(client.add_version(hash.clone(), version_hash.clone(), version_title, metadata.clone()).is_ok());

        // Test document signing
        let signature = Signature {
            signer: signers.get(0).unwrap(),
            timestamp: env.ledger().timestamp(),
            signature_data: BytesN::random(&env),
            claim_reference: BytesN::random(&env),
        };
        assert!(client.sign_document(hash.clone(), signature).is_ok());

        // Verify document
        let document = client.verify_document(hash).unwrap();
        assert_eq!(document.status, DocumentStatus::Active);
        assert_eq!(document.current_version, 1);
    }

    #[test]
    fn test_authority_management() {
        let (env, admin, client) = setup();

        // Register authority
        let authority = Address::random(&env);
        env.set_source_account(admin);
        assert!(client.register_authority(authority.clone()).is_ok());

        // Add claim
        let user = Address::random(&env);
        let claim = IdentityClaim {
            authority: authority.clone(),
            claim_type: symbol_short!("ID"),
            claim_value: BytesN::random(&env),
            signature: BytesN::random(&env),
            issued_at: env.ledger().timestamp(),
            expires_at: env.ledger().timestamp() + 86400,
            metadata: Map::new(&env),
        };
        
        env.set_source_account(authority);
        assert!(client.add_claim(user.clone(), claim).is_ok());
    }

    #[test]
    fn test_document_status_update() {
        let (env, _admin, client) = setup();

        // Create document
        let hash = BytesN::random(&env);
        let title = String::from_slice(&env, "Test Document");
        let signers = vec![&env, Address::random(&env)];
        let metadata = Map::new(&env);
        
        client.create_document(hash.clone(), title, signers, metadata).unwrap();

        // Update status
        assert!(client.update_status(hash.clone(), DocumentStatus::Revoked).is_ok());

        // Verify status
        let document = client.verify_document(hash).unwrap();
        assert_eq!(document.status, DocumentStatus::Revoked);
    }

    #[test]
    fn test_configuration_management() {
        let (env, admin, client) = setup();

        // Update config
        env.set_source_account(admin);
        let config_key = MAX_SIGN;
        let config_value = String::from_slice(&env, "5");
        assert!(client.update_config(config_key.clone(), config_value.clone()).is_ok());

        // Verify config
        let result = client.get_config(config_key).unwrap();
        assert_eq!(result, config_value);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_unauthorized_actions() {
        let (env, _admin, client) = setup();

        // Try to register authority from non-admin account
        let unauthorized = Address::random(&env);
        env.set_source_account(unauthorized);
        
        let authority = Address::random(&env);
        client.register_authority(authority).unwrap();
    }

    #[test]
    fn test_multiple_signatures() {
        let (env, _admin, client) = setup();

        // Create document with multiple signers
        let hash = BytesN::random(&env);
        let title = String::from_slice(&env, "Multi-Sig Document");
        let signers = vec![
            &env,
            Address::random(&env),
            Address::random(&env),
            Address::random(&env)
        ];
        let metadata = Map::new(&env);
        
        client.create_document(hash.clone(), title, signers.clone(), metadata).unwrap();

        // Add signatures
        for i in 0..signers.len() {
            let signer = signers.get(i).unwrap();
            let signature = Signature {
                signer: signer.clone(),
                timestamp: env.ledger().timestamp(),
                signature_data: BytesN::random(&env),
                claim_reference: BytesN::random(&env),
            };
            
            env.set_source_account(signer);
            assert!(client.sign_document(hash.clone(), signature).is_ok());
        }

        // Verify all signatures are present
        let document = client.verify_document(hash).unwrap();
        let current_version = document.versions.get(document.current_version as u32).unwrap();
        assert_eq!(current_version.signatures.len(), signers.len());
        assert_eq!(document.status, DocumentStatus::Active);
    }

    #[test]
    fn test_expired_claims() {
        let (env, admin, client) = setup();

        // Register authority
        let authority = Address::random(&env);
        env.set_source_account(admin);
        client.register_authority(authority.clone()).unwrap();

        // Add expired claim
        let user = Address::random(&env);
        let claim = IdentityClaim {
            authority: authority.clone(),
            claim_type: symbol_short!("ID"),
            claim_value: BytesN::random(&env),
            signature: BytesN::random(&env),
            issued_at: env.ledger().timestamp(),
            expires_at: env.ledger().timestamp() - 1, // Expired
            metadata: Map::new(&env),
        };
        
        env.set_source_account(authority);
        assert!(client.add_claim(user, claim).is_err());
    }

    #[test]
    fn test_user_documents() {
        let (env, _admin, client) = setup();

        // Create multiple documents
        let user = Address::random(&env);
        env.set_source_account(user.clone());

        let doc1_hash = BytesN::random(&env);
        let doc2_hash = BytesN::random(&env);
        let title = String::from_slice(&env, "Test Document");
        let signers = vec![&env, user.clone()];
        let metadata = Map::new(&env);

        // Create documents
        client.create_document(doc1_hash.clone(), title.clone(), signers.clone(), metadata.clone()).unwrap();
        client.create_document(doc2_hash.clone(), title, signers, metadata).unwrap();

        // Get user documents
        let user_docs = client.get_user_documents(user).unwrap();
        assert_eq!(user_docs.len(), 2);
        assert!(user_docs.contains(&doc1_hash));
        assert!(user_docs.contains(&doc2_hash));
    }

    #[test]
    fn test_document_not_found() {
        let (env, _admin, client) = setup();

        let hash = BytesN::random(&env);
        assert!(client.verify_document(hash).is_err());
    }

    #[test]
    fn test_invalid_authority() {
        let (env, _admin, client) = setup();

        // Try to add claim without being registered authority
        let unauthorized = Address::random(&env);
        env.set_source_account(unauthorized.clone());

        let user = Address::random(&env);
        let claim = IdentityClaim {
            authority: unauthorized,
            claim_type: symbol_short!("ID"),
            claim_value: BytesN::random(&env),
            signature: BytesN::random(&env),
            issued_at: env.ledger().timestamp(),
            expires_at: env.ledger().timestamp() + 86400,
            metadata: Map::new(&env),
        };

        assert!(client.add_claim(user, claim).is_err());
    }
}
