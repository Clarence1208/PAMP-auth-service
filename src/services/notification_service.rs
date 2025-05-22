use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailNotification {
    pub to: String,
    pub subject: String,
    pub message: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buttonText: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("API error: {0}")]
    ApiError(String),

    #[error("HTTP client error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Environment variable not set: {0}")]
    EnvError(String),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Sends an email notification to a teacher after they've registered
pub async fn send_teacher_registration_notification(
    teacher_email: &str,
    teacher_first_name: &str,
) -> Result<(), NotificationError> {
    // Get the front URL from environment variables
    let frontend_url = env::var("FRONTEND_URL")
        .map_err(|_| NotificationError::EnvError("FRONTEND_URL".to_string()))?;

    let student_batch_url = format!("{}/students/batch", frontend_url);

    let message = format!(
        "Hello {},\n\n\
        Welcome to PAMP! We are excited to have you on board as a teacher.\n\n\
        You can now start creating student batches to manage your classes efficiently. \
        Use the button below to create your first student batch.\n\n\
        Thank you for choosing PAMP for your educational needs.\n\n\
        The PAMP Team\
        {}",
        teacher_first_name, student_batch_url
    );

    let notification = EmailNotification {
        to: teacher_email.to_string(),
        subject: "Welcome to PAMP - Teacher Registration".to_string(),
        message,
        from: "noreply@edulor.fr".to_string(),
        buttonText: Some("Create your first Student Batch".to_string()),
    };

    send_email_notification(&notification).await
}

/// Sends an email notification to a student after they've been registered by a teacher
pub async fn send_student_registration_notification(
    student_email: &str,
    student_first_name: &str,
    teacher_first_name: &str,
    teacher_last_name: &str,
    teacher_email: &str,
) -> Result<(), NotificationError> {
    // Get the front URL from environment variables
    let front_url = env::var("FRONTEND_URL")
        .map_err(|_| NotificationError::EnvError("FRONTEND_URL not set".to_string()))?;

    let login_url = format!("{}/login", front_url);

    let message = format!(
        "Hello {},\n\n\
        We are excited to have you on board. You have been registered to PAMP by {} {}.\n\n \
        You can now access the PAMP platform to enhance your learning experience. Access to PAMP through the button down here !\n\n\
        If you believe this registration was made in error, please contact your teacher \
        at {}.\n\n\
        Thank you,\nThe PAMP Team\
        {}",
        student_first_name, teacher_first_name, teacher_last_name, teacher_email, login_url
    );

    let notification = EmailNotification {
        to: student_email.to_string(),
        subject: "Welcome to PAMP".to_string(),
        message,
        from: "noreply@edulor.fr".to_string(),
        buttonText: Some("Connect to PAMP".to_string()),
    };

    send_email_notification(&notification).await
}

/// Sends an email notification using the notification API
async fn send_email_notification(
    notification: &EmailNotification,
) -> Result<(), NotificationError> {
    let client = Client::new();

    // Prepare notification data with the button URL included in the message
    let notification_data = serde_json::to_value(notification)?;

    // Get API key from environment variables or use default for local development
    let api_key = env::var("NOTIFICATION_API_KEY")
        .map_err(|_| NotificationError::EnvError("NOTIFICATION_API_KEY".to_string()))?;

    let response = client
        .post("https://b7ywphvnv6.execute-api.eu-west-1.amazonaws.com/prod/notify/email")
        .header("Content-Type", "application/json")
        .header("X-Api-Key", api_key)
        .json(&notification_data)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(NotificationError::ApiError(format!(
            "API returned error: {} - {}",
            status, error_text
        )));
    }

    Ok(())
}
