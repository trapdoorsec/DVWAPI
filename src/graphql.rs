use async_graphql::{Context, EmptySubscription, Object, Schema, SimpleObject};
use serde::{Deserialize, Serialize};

use crate::models::AppState;

#[derive(SimpleObject, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub name: String,
}

#[derive(SimpleObject)]
pub struct Secret {
    pub key: String,
    pub value: String,
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get all users
    async fn users(&self, ctx: &Context<'_>) -> Vec<User> {
        let state = ctx.data::<AppState>().unwrap();
        let users = state.read().await;
        users
            .iter()
            .map(|u| User {
                id: u.id,
                name: u.name.clone(),
            })
            .collect()
    }

    /// Get user by ID
    async fn user(&self, ctx: &Context<'_>, id: u32) -> Option<User> {
        let state = ctx.data::<AppState>().unwrap();
        let users = state.read().await;
        users.iter().find(|u| u.id == id).map(|u| User {
            id: u.id,
            name: u.name.clone(),
        })
    }

    /// VULNERABILITY: Exposed secrets via GraphQL
    async fn secrets(&self) -> Vec<Secret> {
        vec![
            Secret {
                key: "API_KEY".to_string(),
                value: "sk_live_graphql_12345".to_string(),
            },
            Secret {
                key: "DB_PASSWORD".to_string(),
                value: "graphql_password_123".to_string(),
            },
            Secret {
                key: "JWT_SECRET".to_string(),
                value: "graphql-jwt-secret-key".to_string(),
            },
        ]
    }

    /// VULNERABILITY: System info exposure
    async fn system_info(&self) -> SystemInfo {
        SystemInfo {
            hostname: "prod-api-server-01".to_string(),
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(SimpleObject)]
pub struct SystemInfo {
    hostname: String,
    platform: String,
    arch: String,
    version: String,
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Create a new user
    async fn create_user(&self, ctx: &Context<'_>, name: String) -> User {
        let state = ctx.data::<AppState>().unwrap();
        let mut users = state.write().await;
        let id = users.len() as u32 + 1;
        let user = crate::models::User {
            id,
            name: name.clone(),
        };
        users.push(user);
        User { id, name }
    }

    /// VULNERABILITY: Delete user without authentication
    async fn delete_user(&self, ctx: &Context<'_>, id: u32) -> bool {
        let state = ctx.data::<AppState>().unwrap();
        let mut users = state.write().await;
        if let Some(pos) = users.iter().position(|u| u.id == id) {
            users.remove(pos);
            true
        } else {
            false
        }
    }

    /// VULNERABILITY: Execute arbitrary GraphQL without validation
    async fn execute_query(&self, query: String) -> String {
        format!("Would execute: {}", query)
    }
}

pub type ApiSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub fn create_schema(state: AppState) -> ApiSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .finish()
}
