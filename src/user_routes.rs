use crate::AppState;

use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use sqlx::{
    types::{
        chrono::{self, DateTime, Utc},
        Uuid,
    },
    Error as SqlxError, 
};
use serde::{Deserialize, Serialize};



#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(sqlx::FromRow, Serialize, Deserialize)]
pub struct User {
    user_id: Uuid,
    fullname: String,
    dob: String,
    mob_phone: String,
    email: String,
    passwd: String,
    address: String,
    city: String,
    postcode: String,
    a_created: Option<DateTime<Utc>>,
    acc_level: Option<i32>,
    status: Option<i32>,
}


pub async fn register(
    state: web::Data<AppState>,
    user: web::Json<User>,
) -> actix_web::Result<HttpResponse> { // Changed return type
    let user_id = Uuid::new_v4();
    let a_created = chrono::Utc::now();

    // Hash the password
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2
        .hash_password(user.passwd.as_bytes(), &salt)
        .map_err(actix_web::error::ErrorInternalServerError)?
        .to_string();

    let record = sqlx::query_as::<_, User>(
        "INSERT INTO users (user_id, fullname, email, mob_phone, passwd, address, city, postcode, a_created) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
         RETURNING *",
    )
    .bind(user_id)
    .bind(&user.fullname)
    .bind(&user.email)
    .bind(&user.mob_phone)
    .bind(password_hash)
    .bind(&user.address)
    .bind(&user.city)
    .bind(&user.postcode)
    .bind(a_created)
    .fetch_one(&state.db)
    .await;

    match record {
        Ok(user) => Ok(HttpResponse::Ok().json(user)),
        Err(e) => match e {
            SqlxError::Database(e) => {
                if let Some(pg_error) = e.constraint() {
                    if pg_error.contains("users_email_key") {
                        Ok(HttpResponse::Conflict().json(json!({
                            "error": "Email already exists"
                        })))
                    } else if pg_error.contains("users_mob_phone_key") {
                        Ok(HttpResponse::Conflict().json(json!({
                            "error": "Mobile phone number already exists"
                        })))
                    } else {
                        Ok(HttpResponse::InternalServerError().json(json!({
                            "error": e.to_string()
                        })))
                    }
                } else {
                    Ok(HttpResponse::InternalServerError().json(json!({
                        "error": e.to_string()
                    })))
                }
            }
            _ => Ok(HttpResponse::InternalServerError().json(json!({
                "error": e.to_string()
            }))),
        },
    }
}



pub async fn login(
    state: web::Data<AppState>,
    user_data: web::Json<User>,
) -> actix_web::Result<HttpResponse> { // Changed return type
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&user_data.email)
        .fetch_optional(&state.db)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    match user {
        Some(user) => {
            if verify(&user_data.passwd, &user.passwd).unwrap_or(false) {
                let exp = (chrono::Utc::now() + std::time::Duration::from_secs(60 * 60)).timestamp();
                let claims = Claims {
                    sub: user.email.clone(),
                    exp: exp.try_into().unwrap(),
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(state.jwt_secret.as_ref()),
                )
                .map_err(actix_web::error::ErrorInternalServerError)?;

                Ok(HttpResponse::Ok().json(json!({
                    "token": token,
                    "user": {
                        "email": user.email,
                        "fullname": user.fullname
                    }
                })))
            } else {
                Ok(HttpResponse::Unauthorized().json("Invalid credentials"))
            }
        }
        None => Ok(HttpResponse::Unauthorized().json("User not found")),
    }
}