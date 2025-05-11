use sea_orm::{DatabaseConnection, DbErr};
use uuid::Uuid;

use PAMP_auth_service::{
    entities::user::{RegisterStudentRequest, RegisterTeacherRequest, UserRole},
    services::user_service,
};

async fn setup_test_db() -> Result<DatabaseConnection, DbErr> {
    let db = sea_orm::Database::connect("sqlite::memory:").await?;
    PAMP_auth_service::db::ensure_schema_exists(&db).await?;
    Ok(db)
}

#[tokio::test]
async fn test_create_teacher() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Create teacher request
    let request = RegisterTeacherRequest {
        email: "teacher@example.com".to_string(),
        password: "password123".to_string(),
        first_name: "Test".to_string(),
        last_name: "Teacher".to_string(),
    };

    // Create teacher
    let teacher = user_service::create_teacher(&db, request, Some("hashed_password".to_string()))
        .await
        .unwrap();

    // Check teacher properties
    assert_eq!(teacher.email, "teacher@example.com");
    assert_eq!(teacher.first_name, "Test");
    assert_eq!(teacher.last_name, "Teacher");
    assert_eq!(teacher.role, UserRole::Teacher.to_string());
    assert_eq!(teacher.password_hash, Some("hashed_password".to_string()));
    assert!(teacher.is_active);
}

#[tokio::test]
async fn test_find_by_id() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Create a user
    let request = RegisterTeacherRequest {
        email: "find_by_id@example.com".to_string(),
        password: "password123".to_string(),
        first_name: "Find".to_string(),
        last_name: "ById".to_string(),
    };

    let created_user =
        user_service::create_teacher(&db, request, Some("hashed_password".to_string()))
            .await
            .unwrap();

    // Find the user by ID
    let found_user = user_service::find_by_id(&db, created_user.user_id)
        .await
        .unwrap()
        .unwrap();

    // Check that it's the same user
    assert_eq!(found_user.user_id, created_user.user_id);
    assert_eq!(found_user.email, created_user.email);
}

#[tokio::test]
async fn test_find_by_id_not_found() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Try to find a non-existent user
    let non_existent_id = Uuid::new_v4();
    let result = user_service::find_by_id(&db, non_existent_id)
        .await
        .unwrap();

    // Should return None
    assert!(result.is_none());
}

#[tokio::test]
async fn test_find_by_email() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Create a user
    let request = RegisterTeacherRequest {
        email: "find_by_email@example.com".to_string(),
        password: "password123".to_string(),
        first_name: "Find".to_string(),
        last_name: "ByEmail".to_string(),
    };

    let created_user =
        user_service::create_teacher(&db, request, Some("hashed_password".to_string()))
            .await
            .unwrap();

    // Find the user by email
    let found_user = user_service::find_by_email(&db, &created_user.email)
        .await
        .unwrap()
        .unwrap();

    // Check that it's the same user
    assert_eq!(found_user.user_id, created_user.user_id);
    assert_eq!(found_user.email, created_user.email);
}

#[tokio::test]
async fn test_find_by_email_not_found() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Try to find a non-existent user
    let result = user_service::find_by_email(&db, "nonexistent@example.com")
        .await
        .unwrap();

    // Should return None
    assert!(result.is_none());
}

#[tokio::test]
async fn test_create_students() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Create student requests
    let students = vec![
        RegisterStudentRequest {
            email: "student1@example.com".to_string(),
            first_name: "Student".to_string(),
            last_name: "One".to_string(),
        },
        RegisterStudentRequest {
            email: "student2@example.com".to_string(),
            first_name: "Student".to_string(),
            last_name: "Two".to_string(),
        },
    ];

    // Create students
    let created_students = user_service::create_students(&db, students).await.unwrap();

    // Check that both students were created
    assert_eq!(created_students.len(), 2);

    // Check properties of the first student
    let student1 = &created_students[0];
    assert_eq!(student1.email, "student1@example.com");
    assert_eq!(student1.first_name, "Student");
    assert_eq!(student1.last_name, "One");
    assert_eq!(student1.role, UserRole::Student.to_string());
    assert_eq!(student1.password_hash, None); // Students don't have passwords
    assert!(student1.is_active);

    // Check properties of the second student
    let student2 = &created_students[1];
    assert_eq!(student2.email, "student2@example.com");
    assert_eq!(student2.first_name, "Student");
    assert_eq!(student2.last_name, "Two");
    assert_eq!(student2.role, UserRole::Student.to_string());
    assert_eq!(student2.password_hash, None);
    assert!(student2.is_active);
}

#[tokio::test]
async fn test_create_students_skip_existing() {
    // Setup
    let db = setup_test_db().await.unwrap();

    // Create a student first
    let existing_student = RegisterStudentRequest {
        email: "existing@example.com".to_string(),
        first_name: "Existing".to_string(),
        last_name: "Student".to_string(),
    };

    let students_first_batch = vec![existing_student.clone()];
    user_service::create_students(&db, students_first_batch)
        .await
        .unwrap();

    // Try to create the same student again along with a new one
    let new_student = RegisterStudentRequest {
        email: "new@example.com".to_string(),
        first_name: "New".to_string(),
        last_name: "Student".to_string(),
    };

    let students_second_batch = vec![existing_student, new_student];
    let created_students = user_service::create_students(&db, students_second_batch)
        .await
        .unwrap();

    // Should only create the new student
    assert_eq!(created_students.len(), 1);
    assert_eq!(created_students[0].email, "new@example.com");
}
