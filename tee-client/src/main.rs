mod aws;
mod azure;
mod bucket;
mod credentials;
mod enum_names;
mod ovh;
mod report;
mod runtime;
mod support_fn;
mod vector;
mod wrappers;
use bollard::Docker;
use bucket::connect_to_minio_bucket;
use credentials::is_json_file_correct;
use credentials::{
    generate_tee_client_certificate, get_collaboration_info_data, get_sts_credentials,
};
use enum_names::Mode;
use enum_names::Owner;
use report::{collect_evidence, attest_to_inspector_with_csr, attest_to_inspector};
use runtime::docker_connect;
use support_fn::{s3_path_split_bucket, write_to_log};
use wrappers::create_and_mount;
use wrappers::download_sev_binaries;
extern crate chrono;
extern crate rcgen;
extern crate rustls;
extern crate try_catch;
extern crate webpki;
extern crate webpki_roots;
use crate::{
    bucket::{create_bucket_object, retrieve_bucket_item},
    runtime::{check_image_loaded, docker_load_image},
    support_fn::get_file_name,
    wrappers::{
        destroy_environment, run_application_http, run_application_volume, test_application_http,
        test_application_volume,
    },
};
use log::{error, LevelFilter};
use serde_json::Value;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //check in which mode is the tee-client
    let tee_client_mode: Mode;
    if env::args().any(|x| x == *"--attestation-only") {
        tee_client_mode = Mode::AttestationOnly;
    } else if env::args().any(|x| x == *"--basic-attestation") {
        tee_client_mode = Mode::BasicAttestation;
    } else {
        tee_client_mode = Mode::Regular;
    }

    match setup().await {
        Ok(_) => write_to_log("Setup successful!", "message").unwrap(),
        Err(err) => {
            error!("ERROR !!! : {}", err);
            destroy_environment(None, tee_client_mode.clone()).await?;
        },
    };


    match attest(tee_client_mode.clone()).await {
        Ok(_) => {
            write_to_log("Attestation successful!", "message").unwrap();
            let docker = docker_connect().await?;
            let info = get_collaboration_info_data(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_COLLABORATION_DIR"),
                env!("TEE_COLLABORATION_FILE")
            ))
            .unwrap();
            match start_tee_client(&docker, info, tee_client_mode.clone()).await {
                Ok(_) => {
                    write_to_log("Tee-client execution was successful!", "message").unwrap();
                },
                Err(err) => {
                    error!("ERROR !!! : {}", err);
                    destroy_environment(Some(&docker), tee_client_mode.clone()).await?;
                },
            };
        },
        Err(err) => {
            error!("ERROR !!! : {}", err);
            destroy_environment(None, tee_client_mode.clone()).await?;
        },
    };
    Ok(())
}

//
async fn setup() -> Result<(), Box<dyn Error>> {
    //gain sudo power
    sudo::escalate_if_needed()?;

    //init logging
    TermLogger::init(
        //error/warn/info/debug/trace
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )?;

    //set rust backtrace to 1 to have an extended error log
    env::set_var("RUST_BACKTRACE", "full");

    Ok(())
}

//this functions fetches the certificates

pub async fn attest(tee_client_mode: Mode) -> Result<(), Box<dyn Error>> {
    //from the config file, get the necessary information
    let info = get_collaboration_info_data(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_COLLABORATION_DIR"),
        env!("TEE_COLLABORATION_FILE")
    ))
    .unwrap();

    download_sev_binaries().await?;

    create_and_mount(vec![
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")).to_string()
    ])
    .await?;

    //check for the flag attestation only flag, if true, stop tee-client
    match tee_client_mode {
        Mode::AttestationOnly => {
            //do the attestation
            is_json_file_correct(
                &info,
                vec!["enclave", "organization", "application", "dataset"],
            )?;
            generate_tee_client_certificate(&info, Owner::Application).await?;
            collect_evidence(&info, Owner::Application, false, tee_client_mode.clone()).await?;
            attest_to_inspector().await?;

            generate_tee_client_certificate(&info, Owner::Dataset).await?;
            collect_evidence(&info, Owner::Dataset, false, tee_client_mode.clone()).await?;
            attest_to_inspector().await?;

            destroy_environment(None, tee_client_mode.clone()).await?;
            write_to_log("END OF TEE CLIENT !!!", "info").unwrap();
            std::process::exit(1);
        },
        Mode::BasicAttestation => {
            is_json_file_correct(&info, vec!["enclave", "organization"])?;
            //do the attestation
            generate_tee_client_certificate(&info, Owner::Empty).await?;
            collect_evidence(&info, Owner::Empty, false, Mode::BasicAttestation).await?;
            attest_to_inspector().await?;

            destroy_environment(None, tee_client_mode.clone()).await?;
            write_to_log("END OF TEE CLIENT !!!", "info").unwrap();
            std::process::exit(1);
        },
        Mode::Regular => {
            //do the attestation
            is_json_file_correct(
                &info,
                vec!["enclave", "organization", "application", "dataset"],
            )?;
            generate_tee_client_certificate(&info, Owner::Application).await?;
            collect_evidence(&info, Owner::Application, true, tee_client_mode.clone()).await?;
            attest_to_inspector_with_csr(Owner::Application).await?;

            generate_tee_client_certificate(&info, Owner::Dataset).await?;
            collect_evidence(&info, Owner::Dataset, true, tee_client_mode.clone()).await?;
            attest_to_inspector_with_csr(Owner::Dataset).await?;
        },
    }

    Ok(())
}

async fn start_tee_client(
    docker: &Docker,
    info: Value,
    tee_client_mode: Mode,
) -> Result<(), Box<dyn Error>> {
    //collect necessary info from the info file
    let (application_bucket_name, application_file_name) = match s3_path_split_bucket(
        info.get("application")
            .unwrap()
            .get("s3_file_uri")
            .unwrap()
            .as_str()
            .unwrap(),
    ) {
        Some((first, remaining)) => (first, remaining),
        None => return Err("application s3 file uri bad format!".into()),
    };
    let application_result_path = match s3_path_split_bucket(
        info.get("application")
            .unwrap()
            .get("s3_result_uri")
            .unwrap()
            .as_str()
            .unwrap(),
    ) {
        Some((_first, remaining)) => remaining,
        None => return Err("application s3 result uri bad format!".into()),
    };
    let (dataset_bucket_name, dataset_file_name) = match s3_path_split_bucket(
        info.get("dataset")
            .unwrap()
            .get("s3_file_uri")
            .unwrap()
            .as_str()
            .unwrap(),
    ) {
        Some((first, remaining)) => (first, remaining),
        None => return Err("dataset s3 file uri bad format!".into()),
    };
    let dataset_result_path = match s3_path_split_bucket(
        info.get("dataset")
            .unwrap()
            .get("s3_result_uri")
            .unwrap()
            .as_str()
            .unwrap(),
    ) {
        Some((_first, remaining)) => remaining,
        None => return Err("dataset s3 result uri bad format!".into()),
    };
    let enclave_id = info
        .get("enclave")
        .unwrap()
        .get("project_id")
        .unwrap()
        .as_str()
        .unwrap();
    let application_input_type = info
        .get("application")
        .unwrap()
        .get("dataset_input_type")
        .unwrap()
        .as_str()
        .unwrap();
    let application_endpoint = info
        .get("application")
        .unwrap()
        .get("s3_endpoint")
        .unwrap()
        .as_str()
        .unwrap();
    let dataset_endpoint = info
        .get("dataset")
        .unwrap()
        .get("s3_endpoint")
        .unwrap()
        .as_str()
        .unwrap();
    let application_name = get_file_name(application_file_name).unwrap();

    //generate two triplets of sts credentials
    let (application_access_key, application_secret_key, application_session_token) =
        get_sts_credentials(&info, Owner::Application).await?;

    let (dataset_access_key, dataset_secret_key, dataset_session_token) =
        get_sts_credentials(&info, Owner::Dataset).await?;

    //connect to the minio of the app owner
    let mut bucket_application = connect_to_minio_bucket(
        application_bucket_name,
        application_endpoint,
        &application_access_key,
        &application_secret_key,
        &application_session_token,
    )
    .await?;

    //connect to the minio of the dataset owner
    let mut bucket_dataset = connect_to_minio_bucket(
        dataset_bucket_name,
        dataset_endpoint,
        &dataset_access_key,
        &dataset_secret_key,
        &dataset_session_token,
    )
    .await?;

    //download the application image
    retrieve_bucket_item(
        &mut bucket_application,
        application_file_name,
        application_file_name,
        &(format!("{}{}", env!("TEE_ROOT_DIR"), env!("TEE_APPLICATION_DIR"))),
    )
    .await?;

    //load the application image to docker
    docker_load_image(
        docker,
        &(format!(
            "{}{}{}",
            env!("TEE_ROOT_DIR"),
            env!("TEE_APPLICATION_DIR"),
            application_file_name
        )),
    )
    .await?;
    check_image_loaded(docker, application_name).await?;

    //branch out in http input and volume input type
    if application_input_type == "http" {
        let application_entry_port = info
            .get("application")
            .unwrap()
            .get("entry_port")
            .unwrap()
            .as_str()
            .unwrap();
        let application_entry_path = info
            .get("application")
            .unwrap()
            .get("entry_path")
            .unwrap()
            .as_str()
            .unwrap();
        let application_username = info
            .get("application")
            .unwrap()
            .get("username")
            .unwrap()
            .as_str()
            .unwrap();
        let application_password = info
            .get("application")
            .unwrap()
            .get("password")
            .unwrap()
            .as_str()
            .unwrap();
        let application_request_query = info
            .get("application")
            .unwrap()
            .get("request_query")
            .unwrap()
            .as_str()
            .unwrap();

        let outflow_id = run_application_http(
            docker,
            application_name,
            dataset_endpoint,
            dataset_file_name,
            dataset_bucket_name,
            &dataset_access_key,
            &dataset_secret_key,
            &dataset_session_token,
            application_entry_port,
            application_entry_path,
            application_username,
            application_password,
            application_request_query,
        )
        .await?;

        test_application_http(docker, &outflow_id, tee_client_mode.clone()).await?;
    } else if application_input_type == "volume" {
        let application_command = info
            .get("application")
            .unwrap()
            .get("command")
            .unwrap()
            .as_array()
            .unwrap();
        let read_result_file = info
            .get("enclave")
            .unwrap()
            .get("_id")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
            + "_result";
        let result_file = read_result_file.as_str();

        run_application_volume(
            docker,
            &mut bucket_dataset,
            dataset_file_name,
            application_name,
            application_command.to_owned(),
            result_file,
        )
        .await?;

        test_application_volume(docker, result_file, tee_client_mode.clone()).await?;
    } else {
        return Err("input type for the application not recongized".into());
    }

    //upload the results to the two minio buckets
    create_bucket_object(
        &bucket_application,
        &format!("/{}/run_{}.tar", application_result_path, enclave_id),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_RESULT_DIR"),
            env!("RESULT_TMP_FILE")
        ),
    )
    .await?;
    create_bucket_object(
        &bucket_dataset,
        &format!("/{}/run_{}.tar", dataset_result_path, enclave_id),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_RESULT_DIR"),
            env!("RESULT_TMP_FILE")
        ),
    )
    .await?;

    //stop remove the images from docker and umount the folders
    destroy_environment(Some(docker), tee_client_mode.clone()).await?;

    Ok(())
}
