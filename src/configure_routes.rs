use actix_web::web;
use crate::seo_routes::analyze_site;
use crate::user_routes::{login, register};

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .service(
            web::scope("/api")
                .service(
                    web::scope("/auth")
                        .route("/register", web::post().to(register))
                        .route("/login", web::post().to(login))
                )
                .service(
                    web::scope("/seo")
                        .route("/analyze", web::post().to(analyze_site))
                )
        );
}