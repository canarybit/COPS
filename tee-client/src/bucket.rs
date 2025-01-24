extern crate chrono;
extern crate rcgen;
extern crate rustls;
extern crate try_catch;
extern crate webpki;
extern crate webpki_roots;
use crate::support_fn::write_to_log;
use crate::wrappers::create_and_mount;
use log::info;
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use std::fs::File;
use std::io::Write;
use std::{error::Error, str};

//this function connects to an existing s3_bucket given the credentials
pub async fn connect_to_minio_bucket(
    name: &str,
    config: &str,
    access_key: &str,
    secret_key: &str,
    session_token: &str,
) -> Result<Bucket, Box<dyn Error>> {
    write_to_log(
        &format!("===== Connecting to the S3 bucket {} ", name),
        "info",
    )?;

    let s3_endpoint = config.to_owned() + ":" + env!("MINIO_DEFAULT_PORT");
    let bucket = Bucket::new(
        name,
        Region::Custom {
            region: "".to_owned(),
            endpoint: s3_endpoint,
        },
        Credentials {
            access_key: Some(access_key.to_string()),
            secret_key: Some(secret_key.to_string()),
            security_token: None,
            session_token: Some(session_token.to_string()),
            expiration: None,
        },
    )?
    .with_path_style();

    write_to_log("bucket created correctly", "message")?;
    Ok(bucket)
}

//this function download an item from a bucket
pub async fn retrieve_bucket_item(
    bucket: &mut Bucket,
    bucket_item_name: &str,
    local_item_name: &str,
    local_item_path: &str,
) -> Result<File, Box<dyn Error>> {
    write_to_log(&format!("===== Retrieving {}", bucket_item_name), "info")?;

    //create directories and mounting the memory ram
    create_and_mount(vec![local_item_path.to_string()]).await?;

    // set the request timeout to 10 minutes
    bucket.set_request_timeout(Some(std::time::Duration::from_secs(600)));

    let local_item = format!("{}{}", local_item_path, local_item_name);

    // download the object and save it to a local file
    let path = std::path::Path::new(&local_item);
    let directory = path.parent().unwrap();
    std::fs::create_dir_all(directory)?;
    let response_data = bucket.get_object(bucket_item_name).await?;
    let mut file = std::fs::File::create(local_item)?;
    file.write_all(response_data.bytes())
        .expect("Error writing cache file");

    write_to_log("File retrieved correctly", "message")?;
    Ok(file)
}

//this function create an object on the specified bucket
pub async fn create_bucket_object(
    bucket: &Bucket,
    bucket_file_name: &str,
    local_file_name: &str,
) -> Result<(), Box<dyn Error>> {
    write_to_log(
        &format!(
            "===== Creating the object {} on the bucket {}",
            bucket_file_name, bucket.name
        ),
        "info",
    )?;

    // Validate the input parameters
    if bucket_file_name.is_empty() || local_file_name.is_empty() {
        return Err("Bucket file name or local file name cannot be empty.".into());
    }

    // Check the access control
    let response = bucket.head_object(bucket_file_name).await;
    if response.is_ok() {
        info!("Bucket file already exists")
    }

    // Upload the encrypted object to the bucket
    let mut file = tokio::fs::File::open(local_file_name).await?;
    bucket
        .put_object_stream(&mut file, bucket_file_name)
        .await?;

    write_to_log("object created correctly", "message")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{connect_to_minio_bucket, retrieve_bucket_item};
    use crate::bucket::create_bucket_object;
    use crate::credentials::{
        generate_tee_client_certificate, get_collaboration_info_data, get_sts_credentials,
    };
    use crate::enum_names::{Mode, Owner};
    use crate::report::{collect_evidence, attest_to_inspector_with_csr};
    use crate::support_fn::{is_file_existing, test_destroy, test_setup};
    use std::error::Error;
    use std::fs::File;
    use std::io::Write;
    use tokio::fs;

    #[tokio::test]
    async fn test_connect_to_minio_bucket_retrieve_bucket_item() -> Result<(), Box<dyn Error>> {
        test_setup(
            vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR")
                ),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_SAMPLE_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")),
            ],
            true,
        )
        .await?;
        let test_file = "test_file";
        let test_file_path = format!(
            "{}{}{}",
            env!("TEE_ROOT_DIR"),
            env!("TEE_SAMPLE_DIR"),
            test_file
        );
        if std::path::Path::new(&test_file_path).exists() {
            fs::remove_file(&test_file_path).await.unwrap()
        };

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
        let (application_access_key, application_secret_key, application_session_token) =
            get_sts_credentials(&info, Owner::Application).await?;

        match connect_to_minio_bucket(
            "unit-test",
            "https://test.minio.cops.io",
            &application_access_key,
            &application_secret_key,
            &application_session_token,
        )
        .await
        {
            Ok(mut bucket) => {
                retrieve_bucket_item(
                    &mut bucket,
                    test_file,
                    test_file,
                    &format!("{}{}", env!("TEE_ROOT_DIR"), env!("TEE_SAMPLE_DIR"),),
                )
                .await?;
                assert!(std::path::Path::new(&test_file_path).exists());
                assert!(is_file_existing(&test_file_path));
            },
            Err(err) => {
                return Err(err.into());
            },
        };

        fs::remove_file(test_file_path).await.unwrap();
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_connect_to_minio_bucket_create_bucket_item() -> Result<(), Box<dyn Error>> {
        test_setup(
            vec![
                concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_CERTS_DIR"),
                    env!("TEE_APPLICATION_CERTS_DIR")
                ),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_SAMPLE_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR")),
                concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")),
            ],
            true,
        )
        .await?;

        //test file creation
        let test_file = "new_test_file";
        let test_file_path = format!(
            "{}{}{}",
            env!("TEE_ROOT_DIR"),
            env!("TEE_SAMPLE_DIR"),
            test_file
        );
        let mut file = File::create(&test_file_path)?;
        file.write_all(b"Cool test file!")?;

        //generate report
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
        let (application_access_key, application_secret_key, application_session_token) =
            get_sts_credentials(&info, Owner::Application).await?;

        match connect_to_minio_bucket(
            "unit-test",
            "https://test.minio.cops.io",
            &application_access_key,
            &application_secret_key,
            &application_session_token,
        )
        .await
        {
            Ok(bucket) => {
                create_bucket_object(&bucket, test_file, &test_file_path).await?;
                let (_head_object_result, code) = bucket.head_object(test_file).await?;
                assert_eq!(code, 200);
            },
            Err(err) => {
                return Err(err.into());
            },
        };

        fs::remove_file(test_file_path).await.unwrap();
        test_destroy().await?;
        Ok(())
    }
}
