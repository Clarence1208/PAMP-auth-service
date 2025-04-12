use sea_orm::entity::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    #[sea_orm(unique)]
    pub email: String,
    pub password_hash: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub role: String, // Will store "TEACHER" or "STUDENT"
    pub external_auth_provider: Option<String>,
    pub external_auth_id: Option<String>,
    #[sea_orm(default_value = "true")]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema)]
pub enum UserRole {
    #[serde(rename = "TEACHER")]
    Teacher,
    #[serde(rename = "STUDENT")]
    Student,
}

impl ToString for UserRole {
    fn to_string(&self) -> String {
        match self {
            UserRole::Teacher => "TEACHER".to_string(),
            UserRole::Student => "STUDENT".to_string(),
        }
    }
}

impl From<String> for UserRole {
    fn from(role: String) -> Self {
        match role.as_str() {
            "TEACHER" => UserRole::Teacher,
            "STUDENT" => UserRole::Student,
            _ => UserRole::Student, // Default
        }
    }
}

// Registration request model with validation
#[derive(Debug, Deserialize, Serialize, ToSchema, Validate)]
pub struct RegisterTeacherRequest {
    #[schema(examples("john.doe@email.com"))]
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[schema(examples("password123"))]
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    #[validate(length(min = 1, message = "First name is required"))]
    pub first_name: String,
    #[validate(length(min = 1, message = "Last name is required"))]
    pub last_name: String,
} 