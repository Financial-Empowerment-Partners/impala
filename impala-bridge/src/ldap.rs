use crate::config::Config;
use crate::error::AppError;
use crate::validate::ldap_escape;
use log::{debug, error, info, warn};
use serde::Serialize;
use sqlx::PgPool;
use std::collections::HashMap;

/// Narrow LDAP configuration carried as shared state (`Arc<LdapConfig>`), so the
/// per-account sync handler can reach LDAP without exposing the full `Config`
/// (which holds `ldap_bind_password` and other secrets) to every handler.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub url: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub base_dn: Option<String>,
    pub search_filter: Option<String>,
}

impl LdapConfig {
    pub fn from_config(config: &Config) -> Self {
        LdapConfig {
            url: config.ldap_url.clone(),
            bind_dn: config.ldap_bind_dn.clone(),
            bind_password: config.ldap_bind_password.clone(),
            base_dn: config.ldap_base_dn.clone(),
            search_filter: config.ldap_search_filter.clone(),
        }
    }
}

/// Profile attributes pulled from a directory entry. All optional — absent
/// directory attributes are left untouched on writeback (via `COALESCE`).
#[derive(Debug, Default, Clone, Serialize)]
pub struct SyncedProfile {
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub affiliation: Option<String>,
}

/// Pure mapper from LDAP attributes to a [`SyncedProfile`]. Standard inetOrgPerson
/// attribute names: givenName / sn / initials / o (falling back to ou).
pub fn map_ldap_attrs(attrs: &HashMap<String, Vec<String>>) -> SyncedProfile {
    let first = |k: &str| attrs.get(k).and_then(|v| v.first()).cloned();
    SyncedProfile {
        first_name: first("givenName"),
        last_name: first("sn"),
        middle_name: first("initials"),
        affiliation: first("o").or_else(|| first("ou")),
    }
}

/// Connect to the configured LDAP server and (if credentials are configured)
/// bind. Returns the bound `Ldap` handle. Shared by the startup `directory_sync`
/// and the per-account `sync_account_profile`.
async fn connect_bind(cfg: &LdapConfig) -> Result<ldap3::Ldap, AppError> {
    let url = cfg
        .url
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("LDAP is not configured".to_string()))?;

    let (conn, mut ldap) = ldap3::LdapConnAsync::new(url).await.map_err(|e| {
        error!("ldap: failed to connect to {}: {}", url, e);
        AppError::InternalError("LDAP connection failed".to_string())
    })?;

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            error!("ldap: connection driver error: {}", e);
        }
    });

    if let (Some(bind_dn), Some(bind_pw)) = (&cfg.bind_dn, &cfg.bind_password) {
        match ldap.simple_bind(bind_dn, bind_pw).await {
            Ok(result) if result.rc == 0 => {
                debug!("ldap: bind successful as {}", bind_dn);
            }
            Ok(result) => {
                error!(
                    "ldap: bind failed (rc={}, message={})",
                    result.rc, result.text
                );
                let _ = ldap.unbind().await;
                return Err(AppError::InternalError("LDAP bind failed".to_string()));
            }
            Err(e) => {
                error!("ldap: bind error: {}", e);
                return Err(AppError::InternalError("LDAP bind failed".to_string()));
            }
        }
    }

    Ok(ldap)
}

/// Force a directory re-pull for a single account and write the result back into
/// `impala_account`. Only name/affiliation fields are updated; absent directory
/// attributes leave existing values intact. Sets `profile_synced_at = NOW()`.
///
/// Errors: `BadRequest` if LDAP is unconfigured; `NotFound` if the account has
/// no matching directory entry; `InternalError` on connection/search/DB failure.
pub async fn sync_account_profile(
    pool: &PgPool,
    cfg: &LdapConfig,
    payala_account_id: &str,
) -> Result<SyncedProfile, AppError> {
    let base_dn = cfg.base_dn.clone().unwrap_or_default();
    let filter_template = cfg
        .search_filter
        .clone()
        .unwrap_or_else(|| "(uid={})".to_string());
    let filter = filter_template.replace("{}", &ldap_escape(payala_account_id));

    let mut ldap = connect_bind(cfg).await?;

    let search = ldap
        .search(
            &base_dn,
            ldap3::Scope::Subtree,
            &filter,
            vec!["givenName", "sn", "initials", "o", "ou"],
        )
        .await
        .map_err(|e| {
            error!("sync_account_profile: search error: {}", e);
            AppError::InternalError("LDAP search failed".to_string())
        })?;

    let entries = match search.success() {
        Ok((entries, _res)) => entries,
        Err(e) => {
            error!("sync_account_profile: search result error: {}", e);
            let _ = ldap.unbind().await;
            return Err(AppError::InternalError("LDAP search failed".to_string()));
        }
    };

    let profile = match entries.into_iter().next() {
        Some(entry) => {
            let se = ldap3::SearchEntry::construct(entry);
            map_ldap_attrs(&se.attrs)
        }
        None => {
            let _ = ldap.unbind().await;
            warn!(
                "sync_account_profile: account_id={} not found in LDAP (filter={})",
                payala_account_id, filter
            );
            return Err(AppError::NotFound(
                "Account not found in directory".to_string(),
            ));
        }
    };

    let _ = ldap.unbind().await;

    sqlx::query(
        r#"
        UPDATE impala_account
           SET first_name = COALESCE($2, first_name),
               middle_name = COALESCE($3, middle_name),
               last_name = COALESCE($4, last_name),
               affiliation = COALESCE($5, affiliation),
               profile_synced_at = NOW(),
               updated_at = NOW()
         WHERE payala_account_id = $1
        "#,
    )
    .bind(payala_account_id)
    .bind(&profile.first_name)
    .bind(&profile.middle_name)
    .bind(&profile.last_name)
    .bind(&profile.affiliation)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("sync_account_profile: DB update error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    info!(
        "sync_account_profile: synced profile for account_id={}",
        payala_account_id
    );
    Ok(profile)
}

/// Synchronize local accounts with an LDAP directory at startup.
///
/// Connects to the configured LDAP server, iterates over every
/// `payala_account_id` in the `impala_account` table, and performs an
/// LDAP search for each one using the configured filter and base DN. This is a
/// read-only reconciliation check (it only logs found/not-found); per-account
/// writeback is handled on demand by [`sync_account_profile`].
pub async fn directory_sync(pool: &PgPool, config: &Config) {
    if config.ldap_url.is_none() {
        debug!("directory_sync: LDAP_URL not configured, skipping");
        return;
    }
    let cfg = LdapConfig::from_config(config);
    let base_dn = cfg.base_dn.clone().unwrap_or_default();
    let filter_template = cfg
        .search_filter
        .clone()
        .unwrap_or_else(|| "(uid={})".to_string());

    info!("directory_sync: connecting to LDAP (base_dn={})", base_dn);

    let mut ldap = match connect_bind(&cfg).await {
        Ok(ldap) => ldap,
        Err(e) => {
            error!("directory_sync: {}", e);
            return;
        }
    };

    let accounts = sqlx::query_as::<_, (String,)>("SELECT payala_account_id FROM impala_account")
        .fetch_all(pool)
        .await;

    let account_ids = match accounts {
        Ok(rows) => rows,
        Err(e) => {
            error!("directory_sync: failed to query accounts: {}", e);
            let _ = ldap.unbind().await;
            return;
        }
    };

    info!(
        "directory_sync: checking {} account(s) against LDAP directory",
        account_ids.len()
    );

    let mut found = 0u64;
    let mut not_found = 0u64;
    let mut errors = 0u64;

    for (account_id,) in &account_ids {
        // Escape the account_id before inserting into the LDAP filter
        let escaped_id = ldap_escape(account_id);
        let filter = filter_template.replace("{}", &escaped_id);

        match ldap
            .search(&base_dn, ldap3::Scope::Subtree, &filter, vec!["*"])
            .await
        {
            Ok(search_result) => {
                let entries = match search_result.success() {
                    Ok((entries, _res)) => entries,
                    Err(_) => vec![],
                };
                if entries.is_empty() {
                    warn!(
                        "directory_sync: account_id={} NOT found in LDAP (filter={})",
                        account_id, filter
                    );
                    not_found += 1;
                } else {
                    for entry in &entries {
                        let se = ldap3::SearchEntry::construct(entry.clone());
                        debug!(
                            "directory_sync: account_id={} found: dn={} attrs={:?}",
                            account_id,
                            se.dn,
                            se.attrs.keys().collect::<Vec<_>>()
                        );
                    }
                    found += 1;
                }
            }
            Err(e) => {
                error!(
                    "directory_sync: LDAP search error for account_id={}: {}",
                    account_id, e
                );
                errors += 1;
            }
        }
    }

    info!(
        "directory_sync: complete — {} found, {} not found, {} errors (out of {} accounts)",
        found,
        not_found,
        errors,
        account_ids.len()
    );

    let _ = ldap.unbind().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_ldap_attrs_maps_standard_fields() {
        let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
        attrs.insert("givenName".to_string(), vec!["Ada".to_string()]);
        attrs.insert("sn".to_string(), vec!["Lovelace".to_string()]);
        attrs.insert("initials".to_string(), vec!["A".to_string()]);
        attrs.insert("o".to_string(), vec!["Analytical Engines".to_string()]);

        let p = map_ldap_attrs(&attrs);
        assert_eq!(p.first_name.as_deref(), Some("Ada"));
        assert_eq!(p.last_name.as_deref(), Some("Lovelace"));
        assert_eq!(p.middle_name.as_deref(), Some("A"));
        assert_eq!(p.affiliation.as_deref(), Some("Analytical Engines"));
    }

    #[test]
    fn test_map_ldap_attrs_affiliation_falls_back_to_ou() {
        let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
        attrs.insert("ou".to_string(), vec!["Research".to_string()]);
        let p = map_ldap_attrs(&attrs);
        assert_eq!(p.affiliation.as_deref(), Some("Research"));
    }

    #[test]
    fn test_map_ldap_attrs_missing_keys_are_none() {
        let attrs: HashMap<String, Vec<String>> = HashMap::new();
        let p = map_ldap_attrs(&attrs);
        assert!(p.first_name.is_none());
        assert!(p.last_name.is_none());
        assert!(p.middle_name.is_none());
        assert!(p.affiliation.is_none());
    }
}
