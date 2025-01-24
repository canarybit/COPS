extern crate bollard;
use bollard::Docker;
use std::env;
use std::fs::File;
use std::{error::Error, io::Write};

use crate::{
    runtime::docker_run_container_in_out_flow,
    support_fn::{calculate_content_sha256, remove_substring, write_to_log},
};

//this function do the curl rquest to get the signature
pub async fn vector_s3_curl_request(
    url: &str,
    access_key: &str,
    secret_key: &str,
    session_token: &str,
    https_host_name: &str,
) -> Result<(String, String, String), reqwest::Error> {
    write_to_log("===== Starting CURL request for aws sign 4 curl", "info").unwrap();

    let datetime = chrono::Utc::now();
    let mut headers = reqwest::header::HeaderMap::new();
    let host_name = remove_substring(https_host_name, "https://");

    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static(""),
    );
    headers.insert("X-Amz-Security-Token", session_token.parse().unwrap());
    headers.insert(
        "X-Amz-Content-Sha256",
        calculate_content_sha256(b"").parse().unwrap(),
    );
    headers.insert(
        "X-Amz-Date",
        datetime
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("host", host_name.parse().unwrap());

    let sign_request = aws_sign_v4::AwsSign::new(
        "GET",
        url,
        &datetime,
        &headers,
        "us-east-1",
        access_key,
        secret_key,
        "s3",
        "",
    );
    let signature = sign_request.sign();

    let current = datetime.format("%Y%m%dT%H%M%SZ").to_string();
    let date = datetime.format("%Y%m%d").to_string();
    let minio_auth_sign = vector_signature_value(&signature).to_string();

    headers.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

    let client = reqwest::Client::new();
    let response = client.get(url).headers(headers).send().await?;

    write_to_log(&format!("\nStatus: {}", response.status()), "message").unwrap();
    let body = response.text().await?;
    write_to_log(
        &format!("Response body:\n\n{}\n\n curl request successful\n", body),
        "message",
    )
    .unwrap();

    Ok((minio_auth_sign, date, current))
}

//support function for the signature one
pub fn vector_signature_value(input: &str) -> &str {
    let start_index = match input.find("Signature=") {
        Some(index) => index + 10, // Add 10 to skip past the "Signature=" substring
        None => return "",
    };
    &input[start_index..]
}

pub async fn vector_setup(
    minio_endpoint_dataset: &str,
    dataset_file_name: &str,
    dataset_bucket_name: &str,
    dataset_access_key: &str,
    dataset_secret_key: &str,
    dataset_session_token: &str,
    application_entry_port: &str,
    application_entry_path: &str,
    application_username: &str,
    application_password: &str,
    application_request_query: &str,
    minio_auth_sign: &str,
    current: &str,
    date: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let minio_endpoint = format!("MINIO_ENDPOINT={}", minio_endpoint_dataset).to_owned();
    let minio_bucket = format!("MINIO_BUCKET={}", dataset_bucket_name).to_owned();
    let minio_dataset_file = format!("MINIO_FILE={}", dataset_file_name).to_owned();
    let minio_access_key_str = format!("MINIO_ACCESS_KEY={}", dataset_access_key).to_owned();
    let minio_secret_key_str = format!("MINIO_SECRET_KEY={}", dataset_secret_key).to_owned();
    let minio_session_token_str =
        format!("MINIO_SESSION_TOKEN={}", dataset_session_token).to_owned();
    let minio_auth_sign_str = format!("MINIO_AUTH_SIGNATURE={}", minio_auth_sign).to_owned();
    let current_str = format!("CURRENT={}", current).to_owned();
    let date_str = format!("DATE={}", date).to_owned();
    let app_entry_port_str = format!("APP_ENTRY_PORT={}", application_entry_port).to_owned();
    let app_entry_path_str = format!("APP_ENTRY_PATH={}", application_entry_path).to_owned();
    let app_user_str = format!("APP_USER={}", application_username).to_owned();
    let app_psw_str = format!("APP_PASSWORD={}", application_password).to_owned();
    let app_request_str = format!("APP_REQUEST_STRING={}", application_request_query).to_owned();
    let interval_str = format!("INTERVAL={}", env!("VECTOR_INTERVAL")).to_owned();

    let env_var_list: Vec<String> = vec![
        minio_endpoint,
        minio_bucket,
        minio_dataset_file,
        minio_access_key_str,
        minio_secret_key_str,
        minio_session_token_str,
        minio_auth_sign_str,
        current_str,
        date_str,
        app_entry_port_str,
        app_entry_path_str,
        app_user_str,
        app_psw_str,
        app_request_str,
        interval_str,
    ];

    Ok(env_var_list)
}

pub async fn vector_run_container_inflow(
    docker: &Docker,
    minio_endpoint_dataset: &str,
    dataset_file_name: &str,
    dataset_bucket_name: &str,
    dataset_access_key: &str,
    dataset_secret_key: &str,
    dataset_session_token: &str,
    application_entry_port: &str,
    application_entry_path: &str,
    application_username: &str,
    application_password: &str,
    application_request_query: &str,
    minio_auth_sign: &str,
    current: &str,
    date: &str,
    network_name: &str,
) -> Result<(), Box<dyn Error>> {
    write_to_log("===== Creating and running the container inflow", "info").unwrap();

    let res = vector_setup(
        minio_endpoint_dataset,
        dataset_file_name,
        dataset_bucket_name,
        dataset_access_key,
        dataset_secret_key,
        dataset_session_token,
        application_entry_port,
        application_entry_path,
        application_username,
        application_password,
        application_request_query,
        minio_auth_sign,
        current,
        date,
    )
    .await
    .unwrap();
    let env_var_list: Vec<&str> = res.iter().map(|n| &**n).collect();

    //creating inflow.toml and outflow.toml
    generate_vector_inflow_file(
        minio_endpoint_dataset,
        dataset_bucket_name,
        dataset_file_name,
        dataset_session_token,
        current,
        dataset_access_key,
        date,
        minio_auth_sign,
        application_entry_port,
        application_entry_path,
        application_username,
        application_password,
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("VECTOR_PIPELINE_DIR"),
            env!("VECTOR_INFLOW_FILE")
        ),
    )
    .unwrap();

    docker_run_container_in_out_flow(
        docker,
        env!("VECTOR_INFLOW_NAME"),
        network_name,
        &format!(
            "{}{}{}",
            env!("VECTOR_IMAGE_NAME"),
            ":",
            env!("VECTOR_IMAGE_VERSION")
        ),
        Some(vec![concat!(
            env!("TEE_ROOT_DIR"),
            env!("VECTOR_PIPELINE_DIR"),
            "inflow.toml",
            ":/etc/vector/vector.toml:ro"
        )
        .to_string()]),
        Some(env_var_list),
    )
    .await?;

    write_to_log("container created correctly", "message").unwrap();
    Ok(())
}

pub async fn vector_run_container_outflow(
    docker: &Docker,
    minio_endpoint_dataset: &str,
    dataset_file_name: &str,
    dataset_bucket_name: &str,
    dataset_access_key: &str,
    dataset_secret_key: &str,
    dataset_session_token: &str,
    application_entry_port: &str,
    application_entry_path: &str,
    application_username: &str,
    application_password: &str,
    application_request_query: &str,
    minio_auth_sign: &str,
    current: &str,
    date: &str,
    network_name: &str,
) -> Result<String, Box<dyn Error>> {
    write_to_log("===== creating and running the container outflow", "info").unwrap();

    let res = vector_setup(
        minio_endpoint_dataset,
        dataset_file_name,
        dataset_bucket_name,
        dataset_access_key,
        dataset_secret_key,
        dataset_session_token,
        application_entry_port,
        application_entry_path,
        application_username,
        application_password,
        application_request_query,
        minio_auth_sign,
        current,
        date,
    )
    .await
    .unwrap();
    let env_var_list: Vec<&str> = res.iter().map(|n| &**n).collect();

    //creating  outflow.toml
    generate_vector_outflow_file(
        application_entry_port,
        application_username,
        application_password,
        application_request_query,
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("VECTOR_PIPELINE_DIR"),
            env!("VECTOR_OUTFLOW_FILE")
        ),
    )
    .unwrap();

    let outflow_container_id = docker_run_container_in_out_flow(
        docker,
        env!("VECTOR_OUTFLOW_NAME"),
        network_name,
        &format!(
            "{}{}{}",
            env!("VECTOR_IMAGE_NAME"),
            ":",
            env!("VECTOR_IMAGE_VERSION")
        ),
        Some(vec![concat!(
            env!("TEE_ROOT_DIR"),
            env!("VECTOR_PIPELINE_DIR"),
            "outflow.toml",
            ":/etc/vector/vector.toml:ro"
        )
        .to_string()]),
        Some(env_var_list),
    )
    .await?;

    write_to_log("container created correctly", "message").unwrap();
    Ok(outflow_container_id)
}

//this function generate a inflow file
pub fn generate_vector_inflow_file(
    minio_endpoint: &str,
    minio_bucket: &str,
    minio_file: &str,
    minio_session_token: &str,
    current: &str,
    minio_access_key: &str,
    date: &str,
    minio_auth_signature: &str,
    app_entry_port: &str,
    app_entry_path: &str,
    app_user: &str,
    app_password: &str,
    file_path: &str,
) -> std::io::Result<()> {
    write_to_log("===== Creating the inflow configuration file", "info").unwrap();

    let mut file = File::create(file_path)?;
    let content_inflow = format!(
"[sources.s3]
type = \"http_client\"
endpoint = \"{}/{}/{}\"
method = \"GET\"
headers.X-Amz-Security-Token = [\"{}\"]
headers.X-Amz-Content-Sha256 = [\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"]
headers.X-Amz-Date = [\"{}\"]
headers.Authorization = [\"AWS4-HMAC-SHA256 Credential={}/{}/us-east-1/s3/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature={}\"]
headers.Content-Type = [\"\"]
scrape_interval_secs = {}
        
[sinks.console]
inputs = [\"s3\"]
target = \"stdout\"
type = \"console\"
encoding.codec = \"json\"
        
[sinks.http]
type = \"http\"
inputs = [ \"s3\" ]
uri = \"http://{}:{}{}\"
method = \"post\"
auth.strategy = \"basic\"
auth.user = \"{}\"
auth.password = \"{}\"
request.headers.Content-Type = \"application/x-ndjson\"
tls.verify_certificate = false
encoding.codec = \"native_json\"",
    minio_endpoint, //batch.max_bytes = 1e+08 
    minio_bucket,
    minio_file,
    minio_session_token,
    current,
    minio_access_key,
    date,
    minio_auth_signature,
    env!("VECTOR_INTERVAL"),
    env!("APP_NAME"),
    app_entry_port,
    app_entry_path,
    app_user,
    app_password);
    file.write_all(content_inflow.as_bytes())?;

    Ok(())
}

//this function generate a outflow file
pub fn generate_vector_outflow_file(
    app_entry_port: &str,
    app_user: &str,
    app_password: &str,
    app_request_string: &str,
    file_path: &str,
) -> std::io::Result<()> {
    write_to_log("===== Creating the outflow configuration file", "info").unwrap();

    let mut file = File::create(file_path)?;
    let content_outflow = format!(
        "[sources.http]
type = \"http_client\"
endpoint = \"http://{}:{}{}\"
method = \"GET\"
auth.strategy = \"basic\"
auth.user = \"{}\"
auth.password = \"{}\"
headers.Content-Type = [\"application/json\"]
tls.verify_certificate = false
scrape_interval_secs = {}
            
[sinks.console]
type = \"console\"
inputs = [\"http\"]
target = \"stdout\"
encoding.codec = \"raw_message\"
            
[sinks.file]
type = \"file\"
inputs = [\"http\"]
path = \"/tmp/result.txt\"
encoding.codec = \"raw_message\"",
        env!("APP_NAME"),
        app_entry_port,
        app_request_string,
        app_user,
        app_password,
        env!("VECTOR_INTERVAL")
    );

    file.write_all(content_outflow.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io::Read};

    use crate::support_fn::{test_destroy, test_setup};

    use super::*;
    use tempfile::NamedTempFile;
    #[tokio::test]
    async fn test_generate_vector_inflow_file() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // Create a temporary file
        let temp_file = NamedTempFile::new()?;

        // Call the function under test
        let minio_endpoint = "http://minio.example.com";
        let minio_bucket = "mybucket";
        let minio_file = "myfile.txt";
        let minio_session_token = "my-session-token";
        let current = "current";
        let minio_access_key = "access-key";
        let date = "2023-08-17";
        let minio_auth_signature = "auth-signature";
        let app_entry_port = "8080";
        let app_entry_path = "/api";
        let app_user = "user";
        let app_password = "pass";

        generate_vector_inflow_file(
            minio_endpoint,
            minio_bucket,
            minio_file,
            minio_session_token,
            current,
            minio_access_key,
            date,
            minio_auth_signature,
            app_entry_port,
            app_entry_path,
            app_user,
            app_password,
            temp_file.path().to_str().unwrap(),
        )?;

        // Read the content of the generated file
        let mut content = String::new();
        let mut file = std::fs::File::open(temp_file.path())?;
        file.read_to_string(&mut content)?;

        // Define the expected content
        let expected_content = format!(
"[sources.s3]
type = \"http_client\"
endpoint = \"{}/{}/{}\"
method = \"GET\"
headers.X-Amz-Security-Token = [\"{}\"]
headers.X-Amz-Content-Sha256 = [\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"]
headers.X-Amz-Date = [\"{}\"]
headers.Authorization = [\"AWS4-HMAC-SHA256 Credential={}/{}/us-east-1/s3/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature={}\"]
headers.Content-Type = [\"\"]
scrape_interval_secs = {}
        
[sinks.console]
inputs = [\"s3\"]
target = \"stdout\"
type = \"console\"
encoding.codec = \"json\"
        
[sinks.http]
type = \"http\"
inputs = [ \"s3\" ]
uri = \"http://{}:{}{}\"
method = \"post\"
auth.strategy = \"basic\"
auth.user = \"{}\"
auth.password = \"{}\"
request.headers.Content-Type = \"application/x-ndjson\"
tls.verify_certificate = false
encoding.codec = \"native_json\"",
            minio_endpoint,
            minio_bucket,
            minio_file,
            minio_session_token,
            current,
            minio_access_key,
            date,
            minio_auth_signature,
            env!("VECTOR_INTERVAL"),
            env!("APP_NAME"),
            app_entry_port,
            app_entry_path,
            app_user,
            app_password
        );

        // Compare the generated content with the expected content
        assert_eq!(content, expected_content);
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_vector_outflow_file() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // Create a temporary file
        let temp_file = NamedTempFile::new()?;

        // Call the function under test
        let app_entry_port = "8080";
        let app_user = "user";
        let app_password = "pass";
        let app_request_string = "/api/data";
        generate_vector_outflow_file(
            app_entry_port,
            app_user,
            app_password,
            app_request_string,
            temp_file.path().to_str().unwrap(),
        )?;

        // Read the content of the generated file
        let mut content = String::new();
        let mut file = std::fs::File::open(temp_file.path())?;
        file.read_to_string(&mut content)?;

        // Define the expected content
        let expected_content = format!(
            "[sources.http]
type = \"http_client\"
endpoint = \"http://{}:{}{}\"
method = \"GET\"
auth.strategy = \"basic\"
auth.user = \"{}\"
auth.password = \"{}\"
headers.Content-Type = [\"application/json\"]
tls.verify_certificate = false
scrape_interval_secs = {}
            
[sinks.console]
type = \"console\"
inputs = [\"http\"]
target = \"stdout\"
encoding.codec = \"raw_message\"
            
[sinks.file]
type = \"file\"
inputs = [\"http\"]
path = \"/tmp/result.txt\"
encoding.codec = \"raw_message\"",
            env!("APP_NAME"),
            app_entry_port,
            app_request_string,
            app_user,
            app_password,
            env!("VECTOR_INTERVAL")
        );

        // Compare the generated content with the expected content
        assert_eq!(content, expected_content);
        test_destroy().await?;
        Ok(())
    }

    #[test] //TODO
    fn test_signature_curl_request() {}

    #[tokio::test]
    async fn test_get_signature_substring() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        //valid signature
        let input = "SomeDataSignature=abc123";
        assert_eq!(vector_signature_value(input), "abc123");

        //no signature
        let input = "SomeData";
        assert_eq!(vector_signature_value(input), "");

        //no input
        let input = "";
        assert_eq!(vector_signature_value(input), "");
        test_destroy().await?;
        Ok(())
    }
}
