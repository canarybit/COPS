extern crate chrono;
extern crate rcgen;
extern crate rustls;
extern crate try_catch;
extern crate webpki;
extern crate webpki_roots;
use crate::enum_names::Owner;
use crate::support_fn::{check_if_file_exists, write_to_log};
use crate::wrappers::create_and_mount;
use curl::easy::Easy;
use eagre_asn1::der::DER;
use eagre_asn1::types::IA5String;
use log::error;
use openssl::asn1::Asn1Object;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::error::Error;
use std::fs::{create_dir_all, File};
use std::io::BufReader;
use std::io::Read;
use std::{fs, path::Path, str, vec::Vec};
use xml::reader::XmlEvent;
use xml::EventReader;

//This function generate the credentials to connect to minio
pub async fn get_sts_credentials(
    dashboard_config: &Value,
    owner: Owner,
) -> Result<(String, String, String), Box<dyn Error>> {
    write_to_log("===== Getting the access credentials", "info").unwrap();

    let (ssl_key, ssl_cert) = match owner {
        Owner::Application => (
            Path::new(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_APPLICATION_CERTS_DIR"),
                env!("TEE_APPLICATION_PRIVATE_KEY_FILE")
            )),
            Path::new(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_APPLICATION_CERTS_DIR"),
                env!("TEE_APPLICATION_VALIDATION_SIGNED_CERTIFICATE")
            )),
        ),
        Owner::Dataset => (
            Path::new(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_DATA_CERTS_DIR"),
                env!("TEE_DATA_PRIVATE_KEY_FILE")
            )),
            Path::new(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_DATA_CERTS_DIR"),
                env!("TEE_DATA_VALIDATION_SIGNED_CERTIFICATE")
            )),
        ),
        Owner::Empty => (Path::new(""), Path::new("")),
    };

    let mut data = Vec::new();
    let mut handle = Easy::new();

    let mut endpoint = match owner {
        Owner::Application => dashboard_config
            .get("application")
            .unwrap()
            .get("s3_endpoint")
            .unwrap()
            .to_string(),
        Owner::Dataset => dashboard_config
            .get("dataset")
            .unwrap()
            .get("s3_endpoint")
            .unwrap()
            .to_string(),
        Owner::Empty => "".to_string(),
    };
    endpoint = endpoint.replace('\"', "");

    let handle_url_string = format!(
        "{}:{}?Action={}&Version={}&DurationSeconds={}",
        endpoint,
        env!("MINIO_DEFAULT_PORT"),
        env!("MINIO_DEFAULT_ACTION"),
        env!("MINIO_DEFAULT_VERSION"),
        env!("MINIO_DEFAULT_DURATION")
    );

    handle.url(&handle_url_string).unwrap();
    handle.post(true).unwrap();
    handle.ssl_key(ssl_key).unwrap();
    handle.ssl_cert(ssl_cert).unwrap();

    {
        let mut transfer = handle.transfer();
        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }

    let data_string = match str::from_utf8(&data) {
        Ok(v) => v,
        Err(err) => {
            return Err(err.into());
        },
    };

    //extrat the data from the xml
    parse_xml_extract_sts_credentials(data_string)
}

//this function will parse the http response, extracting the credentials
fn parse_xml_extract_sts_credentials(
    xml_str: &str,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    if xml_str.is_empty() {
        return Err("ERROR !!! empty string".into());
    }

    let mut access_key_id = String::new();
    let mut secret_access_key = String::new();
    let mut session_token = String::new();

    let parser = EventReader::new(xml_str.as_bytes());

    let mut inside_access_key_id = false;
    let mut inside_secret_access_key = false;
    let mut inside_session_token = false;

    for e in parser {
        match e {
            Ok(XmlEvent::StartElement { name, .. }) => match name.local_name.as_str() {
                "AccessKeyId" => inside_access_key_id = true,
                "SecretAccessKey" => inside_secret_access_key = true,
                "SessionToken" => inside_session_token = true,
                _ => {},
            },
            Ok(XmlEvent::EndElement { name }) => match name.local_name.as_str() {
                "AccessKeyId" => inside_access_key_id = false,
                "SecretAccessKey" => inside_secret_access_key = false,
                "SessionToken" => inside_session_token = false,
                _ => {},
            },
            Ok(XmlEvent::Characters(text)) => {
                if inside_access_key_id {
                    access_key_id.push_str(&text);
                } else if inside_secret_access_key {
                    secret_access_key.push_str(&text);
                } else if inside_session_token {
                    session_token.push_str(&text);
                }
            },
            _ => {},
        }
    }

    println!("ACCESS_KEY : {}", access_key_id);
    println!("SECRET_KEY : {}", secret_access_key);
    println!("SESSION TOKEN : {}", session_token);

    if check_sts_credentials(&access_key_id, &secret_access_key) {
        write_to_log("access credential generated correctly", "message").unwrap();
    } else {
        error!("ERROR !!! STS credentials are not valid");
        return Err("ERROR !!! empty string".into());
    }

    Ok((access_key_id, secret_access_key, session_token))
}

//this function checks the validty of the sts credentials
pub fn check_sts_credentials(access_key: &str, secret_key: &str) -> bool {
    let mut sts_credentials_checks = false;
    let check1 = check_access_key(access_key);
    let check2 = check_secret_key(secret_key);

    if check1 && check2 {
        sts_credentials_checks = true;
    }

    sts_credentials_checks
}

//this function checks the validty of the access key
pub fn check_access_key(access_key: &str) -> bool {
    // Check if the input length is exactly 10 characters
    if access_key.len() != 20 {
        return false;
    }

    // Check if all characters are either numbers or uppercase letters
    for c in access_key.chars() {
        if !(c.is_ascii_digit() || c.is_ascii_uppercase()) {
            return false;
        }
    }

    true
}

//this function checks the validty of the secret key
pub fn check_secret_key(secret_key: &str) -> bool {
    // Check if the input length is exactly 20 characters
    if secret_key.len() != 40 {
        return false;
    }

    // Check if all characters are either numbers, letters, or "+"
    for c in secret_key.chars() {
        if !(c.is_ascii_alphanumeric() || c == '+') {
            return false;
        }
    }

    true
}

pub fn get_collaboration_info_data(path: &str) -> Result<Value, Box<dyn std::error::Error>> {
    write_to_log("===== Getting config data", "info").unwrap();
    write_to_log(&format!("From: {} ", path), "info")?;

    // Open the file and read its contents
    let config_file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Err("Error opening config file".into()),
    };

    let mut buf_reader = BufReader::new(config_file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;

    // Parse the contents as JSON
    let object = match serde_json::from_str(&contents) {
        Ok(json) => json,
        Err(_) => return Err("Error parsing config file".into()),
    };

    write_to_log("config data retrived correctly", "message").unwrap();
    Ok(object)
}

//This function generate the certificate and the kets, later used to generate the credentials
pub async fn generate_tee_client_certificate(
    dashboard_config: &Value,
    owner: Owner,
) -> Result<(), Box<dyn std::error::Error>> {
    write_to_log(
        "===== Generating certificates and keys for the tee-client owner",
        "info",
    )
    .unwrap();

    match owner {
        Owner::Application => {
            create_and_mount(vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR")
                )
                .to_string(),
            ])
            .await?;
        },
        Owner::Dataset => {
            create_and_mount(vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_DATA_CERTS_DIR")
                )
                .to_string(),
            ])
            .await?;
        },
        Owner::Empty => {
            create_dir_all(concat!(env!("TEE_ROOT_DIR"), env!("TEE_CERTS_DIR")))?;

            if check_if_file_exists(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_PRIVATE_KEY_FILE")
            ))
            .await?
                && check_if_file_exists(concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_PUBLIC_KEY_FILE")
                ))
                .await?
            {
                write_to_log(
                    "The tee-client certificates and keys were already created",
                    "message",
                )
                .unwrap();
                return Ok(());
            }
        },
    }

    // Validate and sanitize inputs
    let country_name = dashboard_config
        .get("organization")
        .unwrap()
        .get("address")
        .unwrap()
        .get("country")
        .unwrap()
        .to_string()
        .replace('\"', "");

    let state_name = dashboard_config
        .get("organization")
        .unwrap()
        .get("address")
        .unwrap()
        .get("state")
        .unwrap()
        .to_string()
        .replace('\"', "");

    //Create nonce value
    let nonce_value: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    // create an EcKey from the binary form of a EcPoint
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let key = EcKey::generate(&group)?;

    let pkey_pem = key.private_key_to_pem().unwrap();
    let public_key: Vec<u8> = key.public_key_to_pem().unwrap();
    let key_pair = PKey::from_ec_key(key)?;
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&key_pair)?;
    let mut x509_name = X509NameBuilder::new()?;

    x509_name.append_entry_by_text("C", &country_name).unwrap();
    x509_name.append_entry_by_text("ST", &state_name).unwrap();
    x509_name
        .append_entry_by_text("O", env!("ORGANISATION_NAME"))
        .unwrap();

    //common name should be empty when generate the tee-client only certificate
    match owner {
        Owner::Application => {
            let common_name = dashboard_config
                .get("application")
                .unwrap()
                .get("s3_policy_name")
                .unwrap()
                .to_string()
                .replace('\"', "");
            x509_name.append_entry_by_text("CN", &common_name).unwrap();
        },
        Owner::Dataset => {
            let common_name = dashboard_config
                .get("dataset")
                .unwrap()
                .get("s3_policy_name")
                .unwrap()
                .to_string()
                .replace('\"', "");
            x509_name.append_entry_by_text("CN", &common_name).unwrap();
        },
        Owner::Empty => {},
    };

    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    let oid = Asn1Object::from_str("1.1.1.1").unwrap();
    let content = IA5String::from(nonce_value).der_bytes().unwrap();
    let extension = SubjectAlternativeName::new()
        .other_name2(oid, &content)
        .build(&req_builder.x509v3_context(None))?;
    let mut stack = openssl::stack::Stack::new().unwrap();
    stack.push(extension).unwrap();
    req_builder.add_extensions(stack.as_ref()).unwrap();
    req_builder.sign(&key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();

    let cert = req.to_pem().unwrap();

    match owner {
        Owner::Application => {
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR"),
                    env!("TEE_APPLICATION_PRIVATE_KEY_FILE")
                ),
                pkey_pem.clone(),
            )?;
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR"),
                    env!("TEE_APPLICATION_PUBLIC_KEY_FILE")
                ),
                public_key.clone(),
            )?;
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_REPORT_DIR"),
                    env!("TEE_APPLICATION_CSR_FILE")
                ),
                cert.clone(),
            )?;
        },
        Owner::Dataset => {
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_DATA_CERTS_DIR"),
                    env!("TEE_DATA_PRIVATE_KEY_FILE")
                ),
                pkey_pem.clone(),
            )?;
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_DATA_CERTS_DIR"),
                    env!("TEE_DATA_PUBLIC_KEY_FILE")
                ),
                public_key.clone(),
            )?;
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_REPORT_DIR"),
                    env!("TEE_DATA_CSR_FILE")
                ),
                cert.clone(),
            )?;
        },
        Owner::Empty => {
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_PRIVATE_KEY_FILE")
                ),
                pkey_pem.clone(),
            )?;
            fs::write(
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_PUBLIC_KEY_FILE")
                ),
                public_key.clone(),
            )?;
        },
    }

    write_to_log("CSR and keys generated correctly", "message").unwrap();
    Ok(())
}

pub fn is_json_file_correct(
    info: &Value,
    keys_to_check: Vec<&str>,
) -> Result<bool, Box<dyn Error>> {
    for key in keys_to_check {
        if !json_has_key(&info, key) {
            write_to_log("Key not found in the Json!", "message").unwrap();
            return Err("info file is malformed!".into());
        }
    }
    Ok(true)
}

pub fn json_has_key(json: &Value, key: &str) -> bool {
    if let Value::Object(map) = json {
        return map.contains_key(key);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support_fn::{test_destroy, test_setup};
    use crate::*;
    use serde_json::json;
    use std::error::Error;
    use tokio::fs;

    #[tokio::test]
    async fn test_get_credential() -> Result<(), Box<dyn Error>> {
        test_setup(
            vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR")
                ),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")),
            ],
            true,
        )
        .await?;

        let info = get_collaboration_info_data(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_COLLABORATION_DIR"),
            env!("TEE_COLLABORATION_FILE")
        ))
        .unwrap();
        generate_tee_client_certificate(&info, Owner::Application).await?;
        collect_evidence(&info, Owner::Application, true, Mode::Regular).await?;
        attest_to_inspector_with_csr(Owner::Application).await?;

        //get sts credentials
        let (access_key, secret_key, session_token) =
            get_sts_credentials(&info, Owner::Application).await?;

        assert!(!access_key.is_empty());
        assert!(!secret_key.is_empty());
        assert!(!session_token.is_empty());
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_xml_extract_sts_credentials() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <AssumeRoleWithCertificateResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithCertificateResult><Credentials><AccessKeyId>EO2KGG9U53ZWOW3G102V</AccessKeyId><SecretAccessKey>SvrgFTk9iEXcx5IWs6dRPERwzOFDjC4ab16RgONJ</SecretAccessKey><SessionToken>SESSION_TOKEN</SessionToken><Expiration>2023-09-06T11:54:44Z</Expiration></Credentials></AssumeRoleWithCertificateResult><ResponseMetadata><RequestId>178249EB2122464F</RequestId></ResponseMetadata></AssumeRoleWithCertificateResponse>
        "#;
        let (access_key, secret_key, session_token) =
            parse_xml_extract_sts_credentials(xml).unwrap();
        assert_eq!(access_key, "EO2KGG9U53ZWOW3G102V");
        assert_eq!(secret_key, "SvrgFTk9iEXcx5IWs6dRPERwzOFDjC4ab16RgONJ");
        assert_eq!(session_token, "SESSION_TOKEN");

        //try with an empty input
        assert!(!parse_xml_extract_sts_credentials("").is_ok());

        //try with an invalid input
        assert!(!parse_xml_extract_sts_credentials("not a valid XML document").is_ok());
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_get_config_data() -> Result<(), Box<dyn Error>> {
        let info_file_content = get_collaboration_info_data(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_COLLABORATION_DIR"),
            env!("TEE_COLLABORATION_FILE")
        ))
        .unwrap();

        let keys_to_check = vec!["enclave", "organization", "application", "dataset"];
        for key in keys_to_check {
            if !json_has_key(&info_file_content, key) {
                write_to_log("Key not found in the Json!", "message").unwrap()
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_generate_tee_client_certificate() -> Result<(), Box<dyn Error>> {
        test_setup(
            vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR")
                ),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")),
            ],
            true,
        )
        .await?;
        // Create a sample dashboard configuration
        let dashboard_config = json!({
            "organization": {
                "address": {
                    "country": "AN",
                    "city": "San Francisco",
                    "state": "California"
                }
            },
            "application": {
                "s3_policy_name": "my_policy"
            },
            "enclave": {
                "cloud_provider":"ovh",
                }
        });
        //try the function with no owner
        let result = generate_tee_client_certificate(&dashboard_config, Owner::Empty).await;
        assert!(result.is_ok());

        let private_key = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_PRIVATE_KEY_FILE")
        );
        let public_key = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_PUBLIC_KEY_FILE")
        );

        assert!(Path::new(private_key).exists());
        assert!(Path::new(public_key).exists());

        let file_private_key = fs::read_to_string(Path::new(private_key)).await?;
        let file_public_key = fs::read_to_string(Path::new(public_key)).await?;
        assert!(!file_private_key.is_empty());
        assert!(!file_public_key.is_empty());

        // Generate the certificate and ensure the function returned Ok
        let result = generate_tee_client_certificate(&dashboard_config, Owner::Application).await;
        assert!(result.is_ok());

        let private_key = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_APPLICATION_CERTS_DIR"),
            env!("TEE_APPLICATION_PRIVATE_KEY_FILE")
        );
        let public_key = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_APPLICATION_CERTS_DIR"),
            env!("TEE_APPLICATION_PUBLIC_KEY_FILE")
        );
        let csr = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_APPLICATION_CSR_FILE")
        );

        assert!(Path::new(private_key).exists());
        assert!(Path::new(public_key).exists());
        assert!(Path::new(csr).exists());

        let file_private_key = fs::read_to_string(Path::new(private_key)).await?;
        let file_public_key = fs::read_to_string(Path::new(public_key)).await?;
        let file_csr = fs::read_to_string(Path::new(csr)).await?;
        assert!(!file_private_key.is_empty());
        assert!(!file_public_key.is_empty());
        assert!(!file_csr.is_empty());
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_tee_client_certificate_no_owner() -> Result<(), Box<dyn Error>> {
        test_setup(
            vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR")
                ),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")),
            ],
            true,
        )
        .await?;
        // Create a sample dashboard configuration
        let dashboard_config = json!({
            "organization": {
                "address": {
                    "country": "AN",
                    "city": "San Francisco",
                    "state": "California"
                }
            },
            "application": {
                "s3_policy_name": "my_policy"
            },
            "enclave": {
                "cloud_provider":"ovh",
                }
        });
        //try the function with no owner
        let result = generate_tee_client_certificate(&dashboard_config, Owner::Empty).await;
        assert!(result.is_ok());

        let private_key = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_PRIVATE_KEY_FILE")
        );
        let public_key = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_PUBLIC_KEY_FILE")
        );

        assert!(Path::new(private_key).exists());
        assert!(Path::new(public_key).exists());

        let file_private_key = fs::read_to_string(Path::new(private_key)).await?;
        let file_public_key = fs::read_to_string(Path::new(public_key)).await?;
        assert!(!file_private_key.is_empty());
        assert!(!file_public_key.is_empty());

        test_destroy().await?;
        Ok(())
    }
}
