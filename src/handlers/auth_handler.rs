// Re-export handlers from other modules for backwards compatibility
pub use crate::handlers::debug_handler::debug_token;
pub use crate::handlers::student_handler::register_students;
pub use crate::handlers::teacher_handler::{login_teacher, register_teacher};
pub use crate::handlers::user_handler::get_current_user; 