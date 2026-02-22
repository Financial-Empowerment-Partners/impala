use crate::config::Config;
use crate::validate::ldap_escape;
use log::{debug, error, info, warn};
use sqlx::PgPool;

/// Synchronize local accounts with an LDAP directory.
///
/// Connects to the configured LDAP server, iterates over every
/// `payala_account_id` in the `impala_account` table, and performs an
/// LDAP search for each one using the configured filter and base DN.
pub async fn directory_sync(pool: &PgPool, config: &Config) {
    let ldap_url = match config.ldap_url {
        Some(ref url) => url.clone(),
        None => {
            debug!("directory_sync: LDAP_URL not configured, skipping");
            return;
        }
    };

    let base_dn = config.ldap_base_dn.clone().unwrap_or_default();
    let filter_template = config
        .ldap_search_filter
        .clone()
        .unwrap_or_else(|| "(uid={})".to_string());

    info!(
        "directory_sync: connecting to LDAP at {} (base_dn={})",
        ldap_url, base_dn
    );

    let (conn, mut ldap) = match ldap3::LdapConnAsync::new(&ldap_url).await {
        Ok(pair) => pair,
        Err(e) => {
            error!(
                "directory_sync: failed to connect to LDAP {}: {}",
                ldap_url, e
            );
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            error!("directory_sync: LDAP connection driver error: {}", e);
        }
    });

    if let (Some(ref bind_dn), Some(ref bind_pw)) =
        (&config.ldap_bind_dn, &config.ldap_bind_password)
    {
        match ldap.simple_bind(bind_dn, bind_pw).await {
            Ok(result) => {
                if result.rc != 0 {
                    error!(
                        "directory_sync: LDAP bind failed (rc={}, message={})",
                        result.rc, result.text
                    );
                    let _ = ldap.unbind().await;
                    return;
                }
                info!("directory_sync: LDAP bind successful as {}", bind_dn);
            }
            Err(e) => {
                error!("directory_sync: LDAP bind error: {}", e);
                return;
            }
        }
    }

    let accounts =
        sqlx::query_as::<_, (String,)>("SELECT payala_account_id FROM impala_account")
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
