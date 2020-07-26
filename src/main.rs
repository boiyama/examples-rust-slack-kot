use aws_lambda_events::event::sqs::SqsEvent;
use chrono::{Duration, FixedOffset, SecondsFormat, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lambda_runtime::{error::HandlerError, lambda, Context};
use log::{error, info};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::error::Error;

#[derive(Debug, Deserialize)]
struct GoogleCredential {
    private_key: String,
    client_email: String,
    token_uri: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Deserialize)]
struct SheetsResponse {
    values: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Payload {
    user_id: String,
    command: String,
    text: String,
    response_url: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(handler);

    Ok(())
}

fn handler(e: SqsEvent, _c: Context) -> Result<(), HandlerError> {
    info!("e: {:?}", e);

    let google_credential: GoogleCredential =
        serde_json::from_str(&env::var("GOOGLE_CREDENTIAL").unwrap()).unwrap();

    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + Duration::minutes(60)).timestamp();

    let my_claims = Claims {
        iss: google_credential.client_email,
        scope: "https://www.googleapis.com/auth/spreadsheets".to_string(),
        aud: google_credential.token_uri,
        exp: exp,
        iat: iat,
    };

    let mut header = Header::default();
    header.typ = Some("JWT".to_string());
    header.alg = Algorithm::RS256;

    let jwt = encode(
        &header,
        &my_claims,
        &EncodingKey::from_rsa_pem(google_credential.private_key.as_bytes()).unwrap(),
    )
    .unwrap();

    let token_body = json!({
        "assertion": jwt,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer"
    });
    info!("token_body: {:?}", token_body);
    let token_response = Client::new()
        .post(&my_claims.aud)
        .json(&token_body)
        .send()
        .unwrap();
    info!("token_response: {:#?}", token_response);

    let token_response_status = token_response.status();
    let token_response_body = token_response.text().unwrap();
    if !token_response_status.is_success() {
        error!("token_url: {}", my_claims.aud);
        error!("token_body: {:?}", token_body);
        error!("token_response_status: {:?}", token_response_status);
        error!("token_response_body: {}", token_response_body);
    }

    let token_response_body = serde_json::from_str::<Value>(&token_response_body).unwrap();
    let access_token = token_response_body
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap();
    info!("access_token: {}", access_token);

    let sheets_url = env::var("SHEETS_URL").unwrap();
    let sheets_response = Client::new()
        .get(&sheets_url)
        .bearer_auth(access_token)
        .send()
        .unwrap();
    info!("sheets_response: {:#?}", sheets_response);

    let sheets_response_status = sheets_response.status();
    let sheets_response_body = sheets_response.text().unwrap();
    if !sheets_response_status.is_success() {
        error!("sheets_url: {}", sheets_url);
        error!("sheets_response_status: {:?}", sheets_response_status);
        error!("sheets_response_body: {}", sheets_response_body);
    }

    let sheets_response_body: SheetsResponse = serde_json::from_str(&sheets_response_body).unwrap();

    let mut slack_kot_user_map = HashMap::new();
    for ids in sheets_response_body.values {
        slack_kot_user_map.insert(ids[0].clone(), ids[1].clone());
    }
    info!("slack_kot_user_map: {:#?}", slack_kot_user_map);

    let kot_access_token = env::var("KOT_ACCESS_TOKEN").unwrap();

    let today = Utc::now().with_timezone(&FixedOffset::east(9 * 3600));
    let date = today.format("%Y-%m-%d").to_string();
    let time = today.to_rfc3339_opts(SecondsFormat::Secs, false);

    for record in &e.records {
        let payload: Payload = serde_qs::from_str(record.body.as_ref().unwrap()).unwrap();
        info!("payload: {:#?}", payload);

        let kot_employee_key = slack_kot_user_map.get(payload.user_id.as_str()).unwrap();
        let kot_url = format!(
            "https://api.kingtime.jp/v1.0/daily-workings/timerecord/{}",
            kot_employee_key
        );

        let kot_body = json!({
            "code": payload.text,
            "date": date,
            "time": time
        });
        info!("kot_body: {:?}", kot_body);

        let kot_response = Client::new()
            .post(&kot_url)
            .bearer_auth(&kot_access_token)
            .json(&kot_body)
            .send()
            .unwrap();
        info!("kot_response: {:#?}", kot_response);

        let kot_response_status = kot_response.status();
        let kot_response_body = kot_response.text().unwrap();
        info!("kot_response_body: {}", kot_response_body);

        if !kot_response_status.is_success() {
            error!("kot_url: {}", kot_url);
            error!("kot_body: {:?}", kot_body);
            error!("kot_response_status: {:?}", kot_response_status);
            error!("kot_response_body: {}", kot_response_body);
        }

        let slack_body =
            json!({ "text": if kot_response_status.is_success() { "Success" } else { "Error" } });
        info!("slack_body: {:?}", slack_body);

        let slack_response = Client::new()
            .post(&payload.response_url)
            .json(&slack_body)
            .send()
            .unwrap();
        info!("slack_response: {:#?}", slack_response);

        let slack_response_status = slack_response.status();

        if !slack_response_status.is_success() {
            error!("slack_url: {}", payload.response_url);
            error!("slack_body: {:?}", slack_body);
            error!("slack_response_status: {:?}", slack_response_status);
        }
    }

    Ok(())
}
