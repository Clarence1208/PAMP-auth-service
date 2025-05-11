use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait,
    QueryFilter, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::entities::user::{ActiveModel, Column, Entity as User, Model, UserRole};
use crate::entities::user::{RegisterStudentRequest, RegisterTeacherRequest};

pub async fn find_by_id(db: &DatabaseConnection, user_id: Uuid) -> Result<Option<Model>, DbErr> {
    User::find()
        .filter(Column::UserId.eq(user_id))
        .one(db)
        .await
}

pub async fn find_by_email(db: &DatabaseConnection, email: &str) -> Result<Option<Model>, DbErr> {
    User::find().filter(Column::Email.eq(email)).one(db).await
}

pub async fn find_by_external_auth(
    db: &DatabaseConnection,
    provider: &str,
    external_id: &str,
) -> Result<Option<Model>, DbErr> {
    User::find()
        .filter(Column::ExternalAuthProvider.eq(provider))
        .filter(Column::ExternalAuthId.eq(external_id))
        .one(db)
        .await
}

pub async fn create_teacher(
    db: &DatabaseConnection,
    request: RegisterTeacherRequest,
    password_hash: Option<String>,
) -> Result<Model, DbErr> {
    let now = Utc::now();

    let user = ActiveModel {
        user_id: Set(Uuid::new_v4()),
        email: Set(request.email),
        password_hash: Set(password_hash),
        first_name: Set(request.first_name),
        last_name: Set(request.last_name),
        role: Set(UserRole::Teacher.to_string()),
        external_auth_provider: Set(None),
        external_auth_id: Set(None),
        is_active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };

    user.insert(db).await
}

pub async fn create_or_update_oauth_user(
    db: &DatabaseConnection,
    email: String,
    first_name: String,
    last_name: String,
    provider: String,
    external_id: String,
) -> Result<Model, DbErr> {
    // Try to find user by email first
    if let Some(existing_user) = find_by_email(db, &email).await? {
        // If user exists but doesn't have this OAuth provider, update them
        if existing_user.external_auth_provider != Some(provider.clone())
            || existing_user.external_auth_id != Some(external_id.clone())
        {
            let mut user_model: ActiveModel = existing_user.into();
            user_model.external_auth_provider = Set(Some(provider));
            user_model.external_auth_id = Set(Some(external_id));
            user_model.updated_at = Set(Utc::now());

            return user_model.update(db).await;
        }

        // If user exists and already has this OAuth provider, return them
        return Ok(existing_user);
    }

    // Try to find user by external auth provider and ID
    if let Some(existing_user) = find_by_external_auth(db, &provider, &external_id).await? {
        return Ok(existing_user);
    }

    // User doesn't exist, create new one
    let now = Utc::now();

    let user = ActiveModel {
        user_id: Set(Uuid::new_v4()),
        email: Set(email),
        password_hash: Set(None),
        first_name: Set(first_name),
        last_name: Set(last_name),
        role: Set(UserRole::Teacher.to_string()), // Default to teacher for OAuth users
        external_auth_provider: Set(Some(provider)),
        external_auth_id: Set(Some(external_id)),
        is_active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };

    user.insert(db).await
}

pub async fn create_student(
    db: &DatabaseTransaction,
    request: RegisterStudentRequest,
) -> Result<Model, DbErr> {
    let now = Utc::now();

    let user = ActiveModel {
        user_id: Set(Uuid::new_v4()),
        email: Set(request.email),
        password_hash: Set(None), // Students don't have passwords initially
        first_name: Set(request.first_name),
        last_name: Set(request.last_name),
        role: Set(UserRole::Student.to_string()),
        external_auth_provider: Set(None),
        external_auth_id: Set(None),
        is_active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };

    user.insert(db).await
}

pub async fn create_students(
    db: &DatabaseConnection,
    requests: Vec<RegisterStudentRequest>,
) -> Result<Vec<Model>, DbErr> {
    // Use a transaction to ensure all students are created or none
    let txn = db.begin().await?;

    let mut created_students = Vec::with_capacity(requests.len());

    for request in requests {
        // Check if student with this email already exists
        let existing_user = User::find()
            .filter(Column::Email.eq(&request.email))
            .one(&txn)
            .await?;

        if existing_user.is_some() {
            // Skip existing students
            continue;
        }

        let student = create_student(&txn, request).await?;
        created_students.push(student);
    }

    txn.commit().await?;

    Ok(created_students)
}
