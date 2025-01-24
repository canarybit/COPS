use execute::Execute;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
extern crate tar;
use crate::aws::attest_aws;
use crate::azure::attest_azure;
use crate::enum_names;
use crate::enum_names::CloudProvider;
use crate::enum_names::Mode;
use crate::ovh::attest_ovh;
use crate::support_fn::get_cloud_provider;
use crate::support_fn::write_to_log;
use enum_names::Owner;
use log::error;
use reqwest::{multipart, Body, Client};
use tokio_util::codec::{BytesCodec, FramedRead};
extern crate reqwest;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use reqwest::header::{HeaderMap, HeaderValue};
use std::io::Read;

//This function generate the report and save it in a .tar file
pub async fn collect_evidence(
    info: &Value,
    owner: Owner,
    csr: bool,
    tee_client_mode: Mode,
) -> Result<(), Box<dyn Error>> {
    write_to_log(
        "===== Generating the evidence extended claims and creating the evidence report",
        "info",
    )
    .unwrap();


    generate_extended_claims_file(info.clone(), tee_client_mode).await?;
    let cloud_provider = get_cloud_provider(info.clone()).await?;

    match cloud_provider {
        CloudProvider::Ovh => attest_ovh(owner, csr).await?,
        CloudProvider::Aws => attest_aws(owner, csr).await?,
        CloudProvider::Azure => attest_azure(owner, csr).await?,
    };

    write_to_log("Evidence extended claims and evidence report generated correctly", "message").unwrap();
    Ok(())
}

//
pub async fn generate_extended_claims_file(config: Value, tee_client_mode: Mode) -> Result<(), Box<dyn Error>> {
    //Get systeminfo parameters
    let infohost = Command::new("hostnamectl")
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let hostout = String::from_utf8(infohost.stdout).unwrap();

    // Iterate over the lines of the file, and in this case print them.
    let lines = hostout.lines();
    let mut line_parts: Vec<String> = Vec::new();
    for line in lines {
        let parts = line.split(": ");
        for part in parts {
            let p = part.to_owned();
            line_parts.push(p);
        }
    }

    //Get the geo location
    let output = Command::new("dig")
        .arg("TXT")
        .arg("+short")
        .arg("myip.opendns.com @resolver1.opendns.com")
        .output()
        .expect("failed to execute process");

    let ipstr = String::from_utf8(output.stdout).unwrap();
    let ip = ipstr.as_str();
    let info = geolocation::find(ip).unwrap();
    let country = info.country;
    let s = country.replace('"', "");
    let outgeo = s.replace("/", "");

    let cloud_provider = config
        .get("enclave")
        .unwrap()
        .get("cloud_provider")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();

    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

    let mut data = json::JsonValue::new_object();
    let line_length = line_parts.len();

    let mut j = 0;
    while j < (line_length - 1) {
        data[line_parts[j].trim()] = line_parts[j + 1].clone().into();
        j += 2;
    }

    data["cloud_provider"] = cloud_provider.into();
    //if tee_client_mode != Mode::BasicAttestation {
    let enclave_id = config
        .get("enclave")
        .unwrap()
        .get("_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    data["enclave_id"] = enclave_id.into();
    //}
    data["time"] = serde_json::to_string(&since_the_epoch.as_nanos())
        .unwrap()
        .into();
    data["geo_location"] = outgeo.into();

    let hex_hash = env!("TEE_CLIENT_HASH");
    data["hash_bin"] = hex_hash.into();

    File::create(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("ENCLAVE_ID")
    ))
    .expect("failed to open enclave id file!");
    fs::write(
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("ENCLAVE_ID")
        ),
        data.to_string(),
    )
    .expect("Unable to write id to file");

    Ok(())
}

//this function generate the signature.sig
pub async fn generate_signature_sig(owner: &Owner) -> Result<(), Box<dyn Error>> {
    let mut filei = File::open(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("ENCLAVE_ID")
    ))?;
    let mut data = Vec::new();
    filei.read_to_end(&mut data).unwrap();

    let mut datap = Vec::new();

    match owner {
        Owner::Application => {
            let mut filep = File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_APPLICATION_CERTS_DIR"),
                env!("TEE_APPLICATION_PRIVATE_KEY_FILE")
            ))?;
            filep.read_to_end(&mut datap).unwrap();
        },
        Owner::Dataset => {
            let mut filep = File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_DATA_CERTS_DIR"),
                env!("TEE_DATA_PRIVATE_KEY_FILE")
            ))?;
            filep.read_to_end(&mut datap).unwrap();
        },
        Owner::Empty => {
            let mut filep = File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_CERTS_DIR"),
                env!("TEE_PRIVATE_KEY_FILE")
            ))?;
            filep.read_to_end(&mut datap).unwrap();
        },
    }

    let key = PKey::private_key_from_pem(&datap)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(&data).unwrap();

    let signature = signer.sign_to_vec().unwrap();
    let mut file = File::create(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("SIGNATURE_SIG")
    ))?;
    file.write_all(&signature)?;

    Ok(())
}

//this function generate the report plaintext file
pub async fn generate_evidence_report_plaintext_file() -> Result<(), Box<dyn Error>> {
    let executable_file2 = concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_AMD_ATTESTATION_CLIENT_DIR"),
        env!("AMD_ATTESTATION_PARSE_REPORT_FILE")
    );
    let mut command2 = Command::new(executable_file2);
    command2.arg(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("AMD_ATTESTATION_BIN_FILE")
    ));
    command2.stdout(Stdio::piped());
    command2.stderr(Stdio::piped());

    let output = command2.execute_output().unwrap();

    if let Some(exit_code1) = output.status.code() {
        if exit_code1 == 0 {
            write_to_log("Evidence report plaintext file created successfully", "info").unwrap();
        } else {
            error!("Evidence report plaintext file creation failed.");
        }
    } else {
        error!("Evidence report plaintext file creation interrupted!");
    }

    let mut newfile = std::fs::File::create(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("AMD_ATTESTATION_REPORT_FILE")
    ))
    .expect("file create failed");
    newfile
        .write_all(output.stdout.as_slice())
        .expect("write failed");
    write_to_log("Evidence report written to file", "info").unwrap();
    Ok(())
}

//this function generates the evidence report binary (filename: guest_report.bin)
pub async fn generate_evidence_report_binary(owner: &Owner) -> Result<(), Box<dyn Error>> {
    let executable_file = concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_AMD_ATTESTATION_CLIENT_DIR"),
        env!("AMD_ATTESTATION_GET_REPORT_FILE")
    );
    let mut command = Command::new(executable_file);

    //make the public key optional
    match owner {
        Owner::Application => {
            command.arg("-f");
            command.arg(
                env!("TEE_ROOT_DIR").to_owned()
                    + env!("TEE_CERTS_DIR")
                    + env!("TEE_APPLICATION_CERTS_DIR")
                    + env!("TEE_APPLICATION_PUBLIC_KEY_FILE"),
            );
        },
        Owner::Dataset => {
            command.arg("-f");
            command.arg(
                env!("TEE_ROOT_DIR").to_owned()
                    + env!("TEE_CERTS_DIR")
                    + env!("TEE_DATA_CERTS_DIR")
                    + env!("TEE_DATA_PUBLIC_KEY_FILE"),
            );
        },
        Owner::Empty => {
            command.arg("-f");
            command.arg(
                env!("TEE_ROOT_DIR").to_owned()
                    + env!("TEE_CERTS_DIR")
                    + env!("TEE_PUBLIC_KEY_FILE"),
            );
        },
    }

    command.arg(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("AMD_ATTESTATION_BIN_FILE")
    ));
    command.arg("-x");

    if let Some(exit_code) = command.execute().unwrap() {
        if exit_code == 0 {
            write_to_log("Evidence report binary file created successfully", "info").unwrap();
        } else {
            error!("ERROR !!! : Evidence report binary file creation failed.");
        }
    } else {
        error!("ERROR !!! : Evidence report binary file creation interrupted!");
    }
    Ok(())
}

//this function do the curl validation request
pub async fn attest_to_inspector_with_csr(owner: Owner) -> Result<String, Box<dyn Error>> {
    let result = inspector_call().await?;
    let is_valid = validate_inspector_call_certificate(result.as_str()).await?;

    if is_valid {
        //if owner is there then
        match owner {
            Owner::Application => {
                let mut data_file = File::create(concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR"),
                    env!("TEE_APPLICATION_VALIDATION_SIGNED_CERTIFICATE")
                ))
                .expect("creation failed");
                data_file
                    .write_all(result.as_bytes())
                    .expect("write failed");
            },
            Owner::Dataset => {
                let mut data_file = File::create(concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_DATA_CERTS_DIR"),
                    env!("TEE_DATA_VALIDATION_SIGNED_CERTIFICATE")
                ))
                .expect("creation failed");
                data_file
                    .write_all(result.as_bytes())
                    .expect("write failed");
            },
            Owner::Empty => {},
        };
    } else {
        return Err("Inspector call not valid".into());
    }

    Ok(result)
}

//this function do the curl validation request
pub async fn attest_to_inspector() -> Result<String, Box<dyn Error>> {
    let result = inspector_call_with_header(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("TEE_ATTESTATION_REPORT_FILE")
    ))
    .await?;
    let is_valid = validate_inspector_call_200(result.as_str()).await?;
    if is_valid {
        Ok(result)
    } else {
        Err("Inspector call not valid".into())
    }
}

//
pub async fn inspector_call() -> Result<String, Box<dyn Error>> {
    let nonce_value: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let client = Client::new();
    let file = tokio::fs::File::open(format!(
        "{}{}{}",
        env!("TEE_ROOT_DIR"),
        env!("TEE_REPORT_DIR"),
        env!("TEE_ATTESTATION_REPORT_FILE")
    ))
    .await?;

    // read file body stream
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);

    //make form part of file
    let some_file = multipart::Part::stream(file_body)
        .file_name(env!("TEE_ATTESTATION_REPORT_FILE"))
        .mime_str("application/x-tar")?;

    //create the multipart form
    let form = multipart::Form::new().part("filedata", some_file);

    //add headers
    let mut headers = HeaderMap::new();
    headers.insert("Nonce", HeaderValue::from_str(&nonce_value).unwrap());

    //send request
    let response = client
        .post(env!("INSPECTOR_DOMAIN"))
        .headers(headers)
        .multipart(form)
        .send()
        .await?;
    let result = response.text().await?;
    println!("Response: {}", result);

    Ok(result)
}

//
pub async fn inspector_call_with_header(evidence_archive: &str) -> Result<String, Box<dyn Error>> {
    let nonce_value: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let client = Client::new();
    let file = tokio::fs::File::open(evidence_archive).await?;

    // read file body stream
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);

    //make form part of file
    let some_file = multipart::Part::stream(file_body)
        .file_name(env!("TEE_ATTESTATION_REPORT_FILE"))
        .mime_str("application/x-tar")?;

    //create the multipart form
    let form = multipart::Form::new().part("filedata", some_file);

    //add headers
    let mut headers = HeaderMap::new();
    headers.insert("Nonce", HeaderValue::from_str(&nonce_value).unwrap());

    //send request
    let response = client
        .post(env!("INSPECTOR_DOMAIN"))
        .headers(headers)
        .multipart(form)
        .send()
        .await?;

    // Get the HTTP status code
    let status_code = response.status().to_string();
    write_to_log(&format!("HTTP Status Code: {:?}", status_code), "message").unwrap();

    Ok(status_code)
}

//
pub async fn validate_inspector_call_certificate(
    inspector_response: &str,
) -> Result<bool, Box<dyn Error>> {
    if inspector_response.contains("Certificate:") {
        Ok(true)
    } else {
        Err("Returned invalid certificate".into())
    }
}

//
pub async fn validate_inspector_call_200(inspector_response: &str) -> Result<bool, Box<dyn Error>> {
    if inspector_response.contains("200 OK") {
        Ok(true)
    } else {
        Err("Evidence validation failed".into())
    }
}

#[cfg(test)]
mod tests {
    use crate::credentials::{generate_tee_client_certificate, get_collaboration_info_data};
    use crate::enum_names::{Mode, Owner};
    use crate::report::{collect_evidence, attest_to_inspector_with_csr, attest_to_inspector};
    use crate::support_fn::test_setup;
    use crate::support_fn::{test_destroy, write_to_log};
    use std::error::Error;
    use std::fs::{self, remove_file};

    #[tokio::test]
    async fn test_collect_evidence_csr() -> Result<(), Box<dyn Error>> {
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

        //test with csr
        let response = collect_evidence(&info, Owner::Application, true, Mode::Regular).await;
        assert!(response.is_ok());
        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_collect_evidence_no_csr() -> Result<(), Box<dyn Error>> {
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

        //test without the csr
        let response = collect_evidence(&info, Owner::Application, false, Mode::Regular).await;
        assert!(response.is_ok());
        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }
        remove_file(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        ))?;

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_collect_evidence_no_owner() -> Result<(), Box<dyn Error>> {
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

        //test with empty owner
        generate_tee_client_certificate(&info, Owner::Empty).await?;
        let response = collect_evidence(&info, Owner::Empty, false, Mode::Regular).await;
        assert!(response.is_ok());
        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }
        remove_file(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        ))?;

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_validate_report_csr() -> Result<(), Box<dyn Error>> {
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

        //test with csr
        let response = collect_evidence(&info, Owner::Application, true, Mode::Regular).await;
        assert!(response.is_ok());

        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }

        let response = attest_to_inspector_with_csr(Owner::Application).await;
        assert!(response.is_ok());
        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_APPLICATION_CERTS_DIR"),
            env!("TEE_APPLICATION_VALIDATION_SIGNED_CERTIFICATE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_validate_evidence_report_no_csr() -> Result<(), Box<dyn Error>> {
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

        //test without the csr
        let response = collect_evidence(&info, Owner::Application, false, Mode::Regular).await;
        assert!(response.is_ok());
        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }

        let response = attest_to_inspector().await;
        assert!(response.is_ok());
        remove_file(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        ))?;

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_validate_report_no_owner() -> Result<(), Box<dyn Error>> {
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

        //test with empty owner
        generate_tee_client_certificate(&info, Owner::Empty).await?;
        let response = collect_evidence(&info, Owner::Empty, false, Mode::Regular).await;
        assert!(response.is_ok());
        match fs::metadata(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        )) {
            Ok(_) => write_to_log("File exists!", "message").unwrap(),
            Err(_) => write_to_log("File does not exist!", "message").unwrap(),
        }

        let response = attest_to_inspector().await;
        assert!(response.is_ok());
        remove_file(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        ))?;

        test_destroy().await?;
        Ok(())
    }
}
