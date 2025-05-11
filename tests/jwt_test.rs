use std::env;
use uuid::Uuid;
use PAMP_auth_service::{auth::jwt, entities::user::UserRole};

// Set up JWT_SECRET for tests
fn setup_jwt_secret() {
    env::set_var("JWT_SECRET", "test_secret_for_jwt_tests");
}

#[test]
fn test_create_and_validate_token() {
    // Set up JWT_SECRET
    setup_jwt_secret();

    // Create a token
    let user_id = Uuid::new_v4();
    let email = "test@example.com";
    let role = UserRole::Teacher;

    let token = jwt::create_token(user_id, email, &role).expect("Failed to create token");

    // Validate the token
    let claims = jwt::validate_token(&token).expect("Failed to validate token");

    // Check claims
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
    assert_eq!(claims.role, role.to_string());

    // Check that iat and exp are set
    assert!(claims.iat > 0);
    assert!(claims.exp > claims.iat);
}

#[test]
fn test_token_expiration() {
    // Set up JWT_SECRET
    setup_jwt_secret();

    use jsonwebtoken::{encode, EncodingKey, Header};

    // Create an expired token manually
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "test_secret".to_string());

    let claims = jwt::Claims {
        sub: Uuid::new_v4().to_string(),
        email: "expired@example.com".to_string(),
        role: UserRole::Teacher.to_string(),
        iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
        exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(), // Expired 1 hour ago
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .unwrap();

    // Validate the token
    let result = jwt::validate_token(&token);

    // Should fail with an error
    assert!(result.is_err());
}

#[test]
fn test_invalid_token_format() {
    // Set up JWT_SECRET
    setup_jwt_secret();

    // Try to validate an invalid token
    let result = jwt::validate_token("invalid.token.format");

    // Should fail with an error
    assert!(result.is_err());
}

#[test]
fn test_token_with_different_roles() {
    // Set up JWT_SECRET
    setup_jwt_secret();

    // Test with Teacher role
    let user_id = Uuid::new_v4();
    let email = "teacher@example.com";
    let role = UserRole::Teacher;

    let token = jwt::create_token(user_id, email, &role).expect("Failed to create token");
    let claims = jwt::validate_token(&token).expect("Failed to validate token");

    assert_eq!(claims.role, "TEACHER");

    // Test with Student role
    let user_id = Uuid::new_v4();
    let email = "student@example.com";
    let role = UserRole::Student;

    let token = jwt::create_token(user_id, email, &role).expect("Failed to create token");
    let claims = jwt::validate_token(&token).expect("Failed to validate token");

    assert_eq!(claims.role, "STUDENT");
}
