use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Error};
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::net::TcpListener;

const MAX_AGE: Duration = Duration::from_secs(15 * 60);
const PRUNE_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    config: Arc<Configuration>,
}

#[derive(Deserialize)]
struct Configuration {
    listen: SocketAddr,

    username: String,
    password: String,

    domain: String,
    hetzner_token: String,

    #[serde(skip_deserializing)]
    zone_id: String,
}

#[derive(Serialize)]
struct JsonError {
    error: String,
}

struct RegistrationForm {
    allowfrom: Vec<String>,
}

impl<'de> Deserialize<'de> for RegistrationForm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RegistrationFormVisitor;

        impl<'de> Visitor<'de> for RegistrationFormVisitor {
            type Value = RegistrationForm;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an RegistrationForm")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut allowfrom = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.to_lowercase().as_str() {
                        "allowfrom" => allowfrom = Some(map.next_value()?),
                        _ => (),
                    }
                }

                Ok(RegistrationForm {
                    allowfrom: allowfrom.ok_or_else(|| A::Error::missing_field("allowfrom"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "UpdateForm",
            &["subdomain", "txt"],
            RegistrationFormVisitor,
        )
    }
}

#[derive(Serialize)]
struct Registration {
    username: String,
    password: String,
    fulldomain: String,
    subdomain: String,
    allowfrom: Vec<String>,
}

async fn register(
    State(state): State<AppState>,
    form: Option<Json<RegistrationForm>>,
) -> Json<Registration> {
    Json(Registration {
        username: state.config.username.clone(),
        password: state.config.password.clone(),
        fulldomain: state.config.domain.clone(),
        subdomain: "@".into(),
        allowfrom: form.map(|Json(form)| form.allowfrom).unwrap_or_default(),
    })
}

struct UpdateForm {
    subdomain: String,
    txt: String,
}

impl<'de> Deserialize<'de> for UpdateForm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UpdateFormVisitor;

        impl<'de> Visitor<'de> for UpdateFormVisitor {
            type Value = UpdateForm;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an UpdateForm")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut subdomain = None;
                let mut txt = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.to_lowercase().as_str() {
                        "subdomain" => subdomain = Some(map.next_value()?),
                        "txt" => txt = Some(map.next_value()?),
                        _ => (),
                    }
                }

                Ok(UpdateForm {
                    subdomain: subdomain.ok_or_else(|| A::Error::missing_field("subdomain"))?,
                    txt: txt.ok_or_else(|| A::Error::missing_field("txt"))?,
                })
            }
        }

        deserializer.deserialize_struct("UpdateForm", &["subdomain", "txt"], UpdateFormVisitor)
    }
}

#[derive(Serialize)]
struct UpdateResponse {
    txt: String,
}

struct XApiUser;

#[axum::async_trait]
impl FromRequestParts<AppState> for XApiUser {
    type Rejection = (StatusCode, Json<JsonError>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(user) = parts.headers.get("X-API-User") else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(JsonError {
                    error: "Invalid username: `X-API-User` header is missing".into(),
                }),
            ));
        };

        if user.as_bytes() == state.config.username.as_bytes() {
            Ok(Self)
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(JsonError {
                    error: "Invalid username: no such user".into(),
                }),
            ))
        }
    }
}

struct XApiKey;

#[axum::async_trait]
impl FromRequestParts<AppState> for XApiKey {
    type Rejection = (StatusCode, Json<JsonError>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(key) = parts.headers.get("X-API-Key") else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(JsonError {
                    error: "Invalid password: `X-API-Key` header is missing".into(),
                }),
            ));
        };

        if key.as_bytes() == state.config.password.as_bytes() {
            Ok(Self)
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(JsonError {
                    error: "Invalid key for user".into(),
                }),
            ))
        }
    }
}

#[derive(Deserialize)]
struct ZonesResponse {
    zones: Vec<Zone>,
    error: Option<HetznerError>,
}

#[derive(Deserialize)]
struct HetznerError {
    message: String,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    name: &'a str,
    zone_id: &'a str,
    ttl: u64,
    #[serde(rename = "type")]
    record_type: &'a str,
    value: &'a str,
}

#[derive(Deserialize)]
struct CreateRecordResponse {
    error: Option<HetznerError>,
}

async fn update(
    State(state): State<AppState>,
    _: XApiUser,
    _: XApiKey,
    Json(UpdateForm { subdomain, txt }): Json<UpdateForm>,
) -> Result<Json<UpdateResponse>, (StatusCode, Json<JsonError>)> {
    let subdomain = if subdomain != "@" {
        format!("_acme-challenge.{subdomain}")
    } else {
        "_acme-challenge".into()
    };

    let record = CreateRecord {
        name: &subdomain,
        zone_id: &state.config.zone_id,
        ttl: MAX_AGE.as_secs(),
        record_type: "TXT",
        value: &txt,
    };

    tracing::info!(?record, "creating record");

    let response_result = state
        .http
        .post("https://dns.hetzner.com/api/v1/records")
        .header("Auth-API-Token", state.config.hetzner_token.as_str())
        .json(&record)
        .send()
        .await;
    match response_result {
        Ok(response) => {
            let status = response.status();
            match response.json::<CreateRecordResponse>().await {
                Ok(_) if status.is_success() => {}
                Ok(response) => {
                    tracing::error!(
                        error = response
                            .error
                            .as_ref()
                            .map(|error| error.message.as_str())
                            .unwrap_or_default(),
                        name = subdomain,
                        value = txt,
                        "failed to create a new record"
                    );

                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(JsonError {
                            error: "failed to create a new record".into(),
                        }),
                    ));
                }
                Err(error) => {
                    tracing::error!(
                        ?error,
                        name = subdomain,
                        value = txt,
                        "failed to parse the create record response"
                    );

                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(JsonError {
                            error: "failed to create a new record".into(),
                        }),
                    ));
                }
            }
        }
        Err(error) => {
            tracing::error!(
                ?error,
                name = subdomain,
                value = txt,
                "failed to create a new record"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JsonError {
                    error: "failed to create a new record".into(),
                }),
            ));
        }
    }

    Ok(Json(UpdateResponse { txt }))
}

async fn zone_pruner(state: AppState) {
    let mut interval = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        interval.tick().await;

        if let Err(error) = prune_zone(&state).await {
            tracing::error!(?error, "failed to prune the zone");
        }
    }
}

#[derive(Deserialize)]
struct ListRecordsResponse {
    records: Vec<Record>,
    error: Option<HetznerError>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Record {
    created: String,
    id: String,
    modified: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
}

async fn prune_zone(state: &AppState) -> Result<(), Error> {
    let records_response = state
        .http
        .get("https://dns.hetzner.com/api/v1/records")
        .query(&[("zone_id", state.config.zone_id.as_str())])
        .header("Auth-API-Token", state.config.hetzner_token.as_str())
        .send()
        .await
        .context("failed send the records request")?;
    let status = records_response.status();
    let records_response = records_response
        .json::<ListRecordsResponse>()
        .await
        .context("failed to parse the zones response")?;
    if !status.is_success() {
        return Err(Error::msg(
            records_response
                .error
                .map(|error| error.message)
                .unwrap_or_default(),
        )
        .context("failed to request the records"));
    }

    let now = Utc::now();

    for record in records_response.records {
        if record.record_type != "TXT"
            || record.name != "_acme-challenge" && !record.name.starts_with("_acme-challenge.")
        {
            continue;
        }

        let modified = DateTime::parse_from_str(&record.modified, "%Y-%m-%d %H:%M:%S%.f %z %Z")
            .with_context(|| format!("failed to parse the modified timestamp on {record:?}"))?
            .with_timezone(&Utc);

        if (now - modified).to_std().unwrap_or(Duration::ZERO) > MAX_AGE {
            tracing::info!(?record, "deleting expired record");
            state
                .http
                .delete(format!(
                    "https://dns.hetzner.com/api/v1/records/{}",
                    record.id
                ))
                .header("Auth-API-Token", state.config.hetzner_token.as_str())
                .send()
                .await
                .with_context(|| format!("failed to delete {record:?}"))?
                .error_for_status()
                .with_context(|| format!("failed to delete {record:?}"))?;
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .compact()
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
        .init();

    let mut config = envy::prefixed("CONFIG_")
        .from_env::<Configuration>()
        .context("failed to load the configuration from the environment")?;

    let listener = TcpListener::bind(config.listen)
        .await
        .context("failed to create the TCP listener")?;

    let http = reqwest::Client::new();

    {
        let zones_response = http
            .get("https://dns.hetzner.com/api/v1/zones")
            .query(&[("name", config.domain.as_str())])
            .header("Auth-API-Token", config.hetzner_token.as_str())
            .send()
            .await
            .context("failed send the zones request")?;
        let zones_status = zones_response.status();
        let mut zones_response = zones_response
            .json::<ZonesResponse>()
            .await
            .context("failed to parse the zones response")?;
        if zones_status.is_success() {
            config.zone_id = zones_response.zones.remove(0).id;
        } else {
            return Err(Error::msg(
                zones_response
                    .error
                    .map(|error| error.message)
                    .unwrap_or_default(),
            )
            .context("failed to request the zones"));
        }
        tracing::info!(
            zone.name = config.domain.as_str(),
            zone.id = config.zone_id.as_str(),
            "fetched the zone ID"
        );
    }

    let state = AppState {
        http,
        config: Arc::new(config),
    };

    let router = Router::new()
        .route("/register", post(register))
        .route("/update", post(update))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(state.clone());

    tokio::spawn(zone_pruner(state));

    axum::serve(listener, router)
        .await
        .context("failed to serve")?;

    Ok(())
}
