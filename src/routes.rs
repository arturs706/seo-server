use crate::AppState;
use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{
    types::{
        chrono::{self, DateTime, Utc},
        Uuid,
    },
    Error as SqlxError, 
};
use std::collections::HashMap; 

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

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdvancedSiteAnalysis {
    url: String,
    meta_info: MetaInfo,
    content_analysis: ContentAnalysis,
    technical_seo: TechnicalSEO,
    backlinks: Vec<Backlink>,
    competitors: Vec<Competitor>,
    rank_tracking: Vec<RankTrackingEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MetaInfo {
    title: String,
    description: String,
    robots: String,
    canonical: String,
    og_tags: HashMap<String, String>,
    structured_data: Vec<String>,
}

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContentAnalysis {
    word_count: i32,
    heading_structure: HashMap<String, i32>,
    keyword_density: HashMap<String, f32>,
    readability_score: f32,
    content_quality_metrics: ContentQualityMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContentQualityMetrics {
    avg_sentence_length: f32,
    paragraph_count: i32,
    image_count: i32,
    alt_text_coverage: f32,
    internal_links: i32,
    external_links: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct TechnicalSEO {
    page_speed_metrics: PageSpeedMetrics,
    mobile_friendly: bool,
    ssl_status: bool,
    crawl_errors: Vec<String>,
    sitemap_status: bool,
    response_time: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct PageSpeedMetrics {
    first_contentful_paint: f32,
    speed_index: f32,
    largest_contentful_paint: f32,
    time_to_interactive: f32,
    total_blocking_time: f32,
    cumulative_layout_shift: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Backlink {
    source_url: String,
    target_url: String,
    anchor_text: String,
    domain_authority: f32,
    follow_status: bool,
    first_seen: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Competitor {
    domain: String,
    overlap_score: f32,
    common_keywords: Vec<String>,
    domain_authority: f32,
    estimated_traffic: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct RankTrackingEntry {
    keyword: String,
    position: i32,
    previous_position: i32,
    search_volume: i32,
    last_updated: String,
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

// Added missing readability score calculation function
fn calculate_readability_score(text: &str) -> f32 {
    let sentences = text.split(['.', '!', '?']).collect::<Vec<_>>();
    let words: Vec<&str> = text.split_whitespace().collect();
    let total_syllables = estimate_syllables(text);

    if sentences.len() == 0 || words.len() == 0 {
        return 0.0;
    }

    // Flesch-Kincaid readability score
    let avg_sentence_length = words.len() as f32 / sentences.len() as f32;
    let avg_syllables_per_word = total_syllables as f32 / words.len() as f32;

    206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)
}

async fn analyze_content(document: &Html) -> ContentAnalysis {
    let text_selector = Selector::parse("body").unwrap();
    let heading_selectors = vec![
        Selector::parse("h1").unwrap(),
        Selector::parse("h2").unwrap(),
        Selector::parse("h3").unwrap(),
    ];
    let paragraph_selector = Selector::parse("p").unwrap();
    let image_selector = Selector::parse("img").unwrap();
    let link_selector = Selector::parse("a").unwrap();

    let text = document
        .select(&text_selector)
        .next()
        .map(|el| el.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();

    let word_count = text.split_whitespace().count() as i32;

    let mut heading_structure = HashMap::new();
    for (i, selector) in heading_selectors.iter().enumerate() {
        let count = document.select(selector).count() as i32;
        heading_structure.insert(format!("h{}", i + 1), count);
    }

    let mut keyword_density = HashMap::new();
    let words: Vec<String> = text.split_whitespace().map(|w| w.to_lowercase()).collect();
    let total_words = words.len() as f32;

    for word in &words {
        *keyword_density.entry(word.clone()).or_insert(0.0) += 1.0;
    }

    for value in keyword_density.values_mut() {
        *value = *value / total_words * 100.0;
    }

    let paragraphs = document.select(&paragraph_selector).count() as i32;
    let images = document.select(&image_selector).count() as i32;
    let images_with_alt = document
        .select(&image_selector)
        .filter(|img| img.value().attr("alt").is_some())
        .count() as f32;

    let links = document.select(&link_selector).collect::<Vec<_>>();
    let (internal_links, external_links) =
        links.iter().fold((0, 0), |(internal, external), link| {
            if let Some(href) = link.value().attr("href") {
                if href.starts_with("/") || href.starts_with("#") {
                    (internal + 1, external)
                } else {
                    (internal, external + 1)
                }
            } else {
                (internal, external)
            }
        });

    ContentAnalysis {
        word_count,
        heading_structure,
        keyword_density,
        readability_score: calculate_readability_score(&text),
        content_quality_metrics: ContentQualityMetrics {
            avg_sentence_length: calculate_avg_sentence_length(&text),
            paragraph_count: paragraphs,
            image_count: images,
            alt_text_coverage: if images > 0 {
                images_with_alt / images as f32 * 100.0
            } else {
                0.0
            },
            internal_links: internal_links as i32,
            external_links: external_links as i32,
        },
    }
}

pub async fn analyze_site(request: web::Json<AnalyzeRequest>) -> actix_web::Result<HttpResponse> {
    let document = match scrape_website(&request.url).await {
        Ok(doc) => doc,
        Err(_) => return Ok(HttpResponse::InternalServerError().json("Failed to scrape website")),
    };

    let meta_info = analyze_meta_info(&document).await;
    let content_analysis = analyze_content(&document).await;
    let technical_seo = analyze_technical_seo(&request.url).await;

    let analysis = AdvancedSiteAnalysis {
        url: request.url.clone(),
        meta_info,
        content_analysis,
        technical_seo,
        backlinks: Vec::new(),
        competitors: Vec::new(),
        rank_tracking: Vec::new(),
    };

    Ok(HttpResponse::Ok().json(analysis))
}

async fn scrape_website(url: &str) -> Result<Html, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; SeoBot/1.0)")
        .build()?;

    let response = client.get(url).send().await?;
    let html = response.text().await?;
    Ok(Html::parse_document(&html))
}

async fn analyze_meta_info(document: &Html) -> MetaInfo {
    let title_selector = Selector::parse("title").unwrap();
    let meta_desc_selector = Selector::parse("meta[name='description']").unwrap();
    let robots_selector = Selector::parse("meta[name='robots']").unwrap();
    let canonical_selector = Selector::parse("link[rel='canonical']").unwrap();
    let og_selector = Selector::parse("meta[property^='og:']").unwrap();

    let title = document
        .select(&title_selector)
        .next()
        .map(|el| el.inner_html())
        .unwrap_or_default();

    let description = document
        .select(&meta_desc_selector)
        .next()
        .and_then(|el| el.value().attr("content"))
        .unwrap_or_default()
        .to_string();

    let robots = document
        .select(&robots_selector)
        .next()
        .and_then(|el| el.value().attr("content"))
        .unwrap_or_default()
        .to_string();

    let canonical = document
        .select(&canonical_selector)
        .next()
        .and_then(|el| el.value().attr("href"))
        .unwrap_or_default()
        .to_string();

    let mut og_tags = HashMap::new();
    for element in document.select(&og_selector) {
        if let (Some(property), Some(content)) = (
            element.value().attr("property"),
            element.value().attr("content"),
        ) {
            og_tags.insert(property.to_string(), content.to_string());
        }
    }

    MetaInfo {
        title,
        description,
        robots,
        canonical,
        og_tags,
        structured_data: Vec::new(),
    }
}

fn calculate_avg_sentence_length(text: &str) -> f32 {
    let sentences = text.split(['.', '!', '?']).collect::<Vec<_>>();
    let total_words: usize = sentences.iter().map(|s| s.split_whitespace().count()).sum();

    if sentences.is_empty() {
        return 0.0;
    }

    total_words as f32 / sentences.len() as f32
}

fn estimate_syllables(text: &str) -> usize {
    text.split_whitespace()
        .map(|word| {
            let word = word.to_lowercase();
            let chars: Vec<char> = word.chars().collect();
            let mut syllable_count = 0;
            let mut prev_is_vowel = false;

            for (i, &c) in chars.iter().enumerate() {
                let is_vowel = "aeiouy".contains(c);
                if is_vowel && (!prev_is_vowel || (i == chars.len() - 1 && c != 'e')) {
                    syllable_count += 1;
                }
                prev_is_vowel = is_vowel;
            }

            std::cmp::max(1, syllable_count)
        })
        .sum()
}

async fn analyze_technical_seo(url: &str) -> TechnicalSEO {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let start = std::time::Instant::now();

    // Check SSL status
    let ssl_status = url.starts_with("https://");

    // Measure response time
    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(_) => {
            return TechnicalSEO {
                page_speed_metrics: PageSpeedMetrics {
                    first_contentful_paint: 0.0,
                    speed_index: 0.0,
                    largest_contentful_paint: 0.0,
                    time_to_interactive: 0.0,
                    total_blocking_time: 0.0,
                    cumulative_layout_shift: 0.0,
                },
                mobile_friendly: false,
                ssl_status,
                crawl_errors: vec!["Failed to connect to site".to_string()],
                sitemap_status: false,
                response_time: 0.0,
            };
        }
    };

    let response_time = start.elapsed().as_secs_f32();
    let sitemap_url = format!("{}/sitemap.xml", url.trim_end_matches('/'));
    let sitemap_status = client
        .get(&sitemap_url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let page_speed_metrics = PageSpeedMetrics {
        first_contentful_paint: response_time * 1.2,
        speed_index: response_time * 1.5,
        largest_contentful_paint: response_time * 2.0,
        time_to_interactive: response_time * 2.5,
        total_blocking_time: response_time * 0.3,
        cumulative_layout_shift: 0.1,
    };

    // Check for crawl errors
    let mut crawl_errors = Vec::new();

    // Check robots.txt
    let robots_url = format!("{}/robots.txt", url.trim_end_matches('/'));
    if client.get(&robots_url).send().await.is_err() {
        crawl_errors.push("robots.txt not found".to_string());
    }
    if !response.status().is_success() {
        crawl_errors.push(format!("HTTP status: {}", response.status()));
    }

    TechnicalSEO {
        page_speed_metrics,
        mobile_friendly: true, 
        ssl_status,
        crawl_errors,
        sitemap_status,
        response_time,
    }
}
