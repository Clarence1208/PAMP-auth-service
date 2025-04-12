use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr, EntityName, Schema};
use sea_orm::sea_query::*;
use std::env;
use std::time::Duration;
use crate::entities::prelude::*;
use tracing::log;

pub async fn init_db() -> Result<DatabaseConnection, DbErr> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    // Set up connection options
    let mut opt = ConnectOptions::new(database_url);
    opt.max_connections(10)
        .min_connections(3)
        .connect_timeout(Duration::from_secs(15))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true)
        .sqlx_logging_level(log::LevelFilter::Info);
    
    // Connect to the database
    Database::connect(opt).await
}

pub async fn ensure_schema_exists(db: &DatabaseConnection) -> Result<(), DbErr> {
    // Generate schema builder
    let builder = db.get_database_backend();
    let schema = Schema::new(builder);
    
    // Create User table if not exists
    let stmt = schema
        .create_table_from_entity(User)
        .if_not_exists()
        .to_owned();
    
    db.execute(builder.build(&stmt)).await?;
    
    // Create index for external_auth_id if needed using Index construct directly
    let column = crate::entities::user::Column::ExternalAuthId;
    let table = crate::entities::user::Entity::table_ref(&Default::default());

    let idx_stmt = IndexCreateStatement::new()
        .name("idx_external_auth_id")
        .table(table)
        .col(column)
        .if_not_exists()
        .to_owned();
    
    db.execute(builder.build(&idx_stmt)).await?;
    
    Ok(())
} 