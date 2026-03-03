use crate::keys::db::{CertEntry, CertKey};
use crate::keys::hash;
use anyhow::{Context, Result, bail};
use openpgp::armor::{Kind, Reader, ReaderMode};
use sequoia_openpgp as openpgp;
use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use std::io::BufReader;
use std::path::Path;
use tracing::warn;

pub fn read_key_file(path: &Path, split_keys: bool) -> Result<Vec<(CertKey, CertEntry)>> {
    let certs = read_certs(path)?;
    if certs.is_empty() {
        return Ok(vec![]);
    }

    let p = StandardPolicy::new();
    let mut results = Vec::new();

    for cert in certs {
        let validated_cert = match cert.with_policy(&p, None) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "Skipping invalid certificate in {}: {}",
                    path.to_string_lossy(),
                    e
                );
                continue;
            }
        };

        for userid in validated_cert.userids() {
            let Some(email) = userid
                .userid()
                .email()
                .context("user id does not have a valid email")?
            else {
                warn!(
                    "user id {} does not have an email, skipping",
                    userid.userid()
                );
                continue;
            };

            let Some((username, cert_key)) = hash::mail_to_key_entry(email)? else {
                bail!("could not hash {email}");
            };

            let mut cert = userid.cert().clone().strip_secret_key_material();
            if split_keys {
                cert = cert.retain_userids(|uid| uid.userid() == userid.userid());
            }

            let cert_entry = CertEntry {
                username,
                cert,
                path: path.as_os_str().into(),
            };

            results.push((cert_key, cert_entry));
        }
    }

    Ok(results)
}

fn read_certs(path: &Path) -> Result<Vec<Cert>> {
    if !path.exists() || !path.is_file() {
        bail!("File {} not found or not a file", path.to_string_lossy());
    }

    let content = std::fs::read(path)?;

    // Validate the public key, tolerate common formatting errors such as erroneous
    // whitespace, but fail on private keys
    let reader = BufReader::new(Reader::from_bytes(
        &content,
        ReaderMode::Tolerant(Some(Kind::PublicKey)),
    ));

    // Use CertParser to handle multiple concatenated certificates
    let parser = match CertParser::from_reader(reader) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                "Could not parse certificates in {}: {}",
                path.to_string_lossy(),
                e
            );
            return Ok(vec![]);
        }
    };

    let mut certs = Vec::new();
    for cert_result in parser {
        match cert_result {
            Ok(cert) => certs.push(cert),
            Err(e) => warn!(
                "Skipping malformed certificate in {}: {}",
                path.to_string_lossy(),
                e
            ),
        }
    }

    Ok(certs)
}
