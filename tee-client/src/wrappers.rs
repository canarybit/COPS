use bollard::{container::DownloadFromContainerOptions, Docker};
use bucket::retrieve_bucket_item;
use s3::Bucket;
use tar::Builder;
extern crate chrono;
extern crate cronjob;
extern crate rcgen;
extern crate rustls;
extern crate try_catch;
extern crate webpki;
extern crate webpki_roots;
use crate::{
    bucket::{self},
    enum_names::Mode,
    runtime::{
        check_image_loaded, create_network, docker_pull, docker_run_container_http,
        docker_run_container_volume, remove_docker_containers, remove_docker_network, remove_docker_images,
    },
    support_fn::{
        curl_sev_guest, generate_random_numeric_string, is_file_existing,
        mount, write_to_log,
    },
    vector::{vector_run_container_inflow, vector_run_container_outflow, vector_s3_curl_request},
};
use core::time;
use serde_json::Value;
use std::env;
use std::process::{self};
use std::{
    error::Error,
    fs::{self, create_dir_all, File},
    thread,
};
extern crate sys_mount;
use sys_mount::{unmount, UnmountFlags};

//this function downlaod sev guest get report and parse report
pub async fn download_sev_binaries() -> Result<(), Box<dyn Error>> {
    create_and_mount(vec![concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_AMD_ATTESTATION_CLIENT_DIR")
    )
    .to_string()])
    .await?;

    curl_sev_guest(
        env!("AMD_ATTESTATION_GET_REPORT_URL"),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_AMD_ATTESTATION_CLIENT_DIR"),
            env!("AMD_ATTESTATION_GET_REPORT_FILE")
        ),
    )
    .await?;

    curl_sev_guest(
        env!("AMD_ATTESTATION_PARSE_REPORT_URL"),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_AMD_ATTESTATION_CLIENT_DIR"),
            env!("AMD_ATTESTATION_PARSE_REPORT_FILE")
        ),
    )
    .await?;

    Ok(())
}

//this function creates and mounts a list of directories
pub async fn create_and_mount(directory_list: Vec<String>) -> Result<(), Box<dyn Error>> {
    create_directories(directory_list.clone())?;
    mount_directories(directory_list.clone()).await?;

    Ok(())
}

//this function creates a directory
pub fn create_directories(directory_list: Vec<String>) -> Result<(), Box<dyn Error>> {
    write_to_log("===== Create all directories paths (if needed)", "info").unwrap();

    for directory in directory_list {
        create_dir_all(directory)?;
    }

    write_to_log("directories created", "message").unwrap();
    Ok(())
}

//this function mount a directory
pub async fn mount_directories(directory_list: Vec<String>) -> Result<(), Box<dyn Error>> {
    write_to_log("===== Mounting new directories", "info").unwrap();

    for directory in directory_list {
        mount(&directory).await?;
    }

    write_to_log("directories mounted", "message").unwrap();
    Ok(())
}

//this is the main code of the tee-client branched to volume
pub async fn run_application_volume(
    docker: &Docker,
    bucket_dataset: &mut Bucket,
    dataset_file_name: &str,
    application_name: &str,
    application_command: Vec<Value>,
    result_file: &str,
) -> Result<(), Box<dyn Error>> {
    //fetch the dataset from minio
    let _dataset_file = retrieve_bucket_item(
        bucket_dataset,
        dataset_file_name,
        dataset_file_name,
        &(format!("{}{}", env!("TEE_ROOT_DIR"), env!("TEE_DATA_DIR"))),
    )
    .await?;

    //check if the image is actually loaded
    check_image_loaded(docker, application_name).await?;

    //run the container for the application
    let bind_folder = std::fs::canonicalize(std::path::PathBuf::from(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_DATA_DIR")
    )))
    .unwrap()
    .into_os_string()
    .into_string()
    .unwrap()
        + ":/folder";
    docker_run_container_volume(
        docker,
        application_name,
        application_command.len(),
        application_command.to_owned(),
        dataset_file_name,
        result_file,
        vec![bind_folder.clone()],
    )
    .await
    .unwrap();
    Ok(())
}

//this is the main code of the tee-client branched to http, it launches all the containers
pub async fn run_application_http(
    docker: &Docker,
    image_name: &str,
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
) -> Result<String, Box<dyn Error>> {
    write_to_log("===== Executing docker run container commands", "info").unwrap();

    //generate network name and create the network
    let network_name = format!(
        "{}{}{}",
        env!("NETWORK_NAME"),
        "-",
        generate_random_numeric_string().await?
    );
    create_network(docker, &network_name).await?;

    //create the signature
    let (minio_auth_sign, date, current) = vector_s3_curl_request(
        &format!(
            "{}/{}/{}",
            minio_endpoint_dataset, dataset_bucket_name, dataset_file_name
        ),
        dataset_access_key,
        dataset_secret_key,
        dataset_session_token,
        minio_endpoint_dataset,
    )
    .await?;

    //check if app and vector images are actually loaded on docker
    docker_pull(concat!(
        env!("VECTOR_IMAGE_NAME"),
        ":",
        env!("VECTOR_IMAGE_VERSION")
    ))
    .await?;
    check_image_loaded(
        docker,
        concat!(env!("VECTOR_IMAGE_NAME"), ":", env!("VECTOR_IMAGE_VERSION")),
    )
    .await?;
    check_image_loaded(docker, image_name).await?;

    //run the application owner app on docker
    docker_run_container_http(
        docker,
        env!("APP_NAME"),
        &network_name,
        image_name,
        None,
        None,
        application_entry_port,
        true,
    )
    .await?;

    //create directories and mounting the memory ram
    create_and_mount(vec![concat!(
        env!("TEE_ROOT_DIR"),
        env!("VECTOR_PIPELINE_DIR")
    )
    .to_string()])
    .await?;

    vector_run_container_inflow(
        docker,
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
        &minio_auth_sign,
        &current,
        &date,
        &network_name,
    )
    .await?;

    let outflow_container_id = vector_run_container_outflow(
        docker,
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
        &minio_auth_sign,
        &current,
        &date,
        &network_name,
    )
    .await?;

    write_to_log("application launched succefully", "message").unwrap();
    Ok(outflow_container_id)
}

//this function just gives a few minutes to let the application run to generate some results
pub async fn test_application_http(
    docker: &Docker,
    container_id: &str,
    tee_client_mode: Mode,
) -> Result<(), Box<dyn Error>> {
    write_to_log("===== Testing the application", "info").unwrap();

    //create directories and mounting the memory ram
    create_and_mount(vec![
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_RESULT_DIR")).to_string()
    ])
    .await?;

    let tries_limit: u64 = env!("TEST_APPLICATION_ATTEMPTS_LIMIT").parse().unwrap();
    let interval: u64 = env!("VECTOR_INTERVAL").parse().unwrap();
    let interval = interval + 5;
    let mut found_result = false;
    let mut tryes = 0;

    while !found_result {
        tryes += 1;
        if tryes > tries_limit {
            destroy_environment(Some(docker), tee_client_mode.clone()).await?;
        }
        write_to_log(&format!("Started a {} seconds timer", interval), "info").unwrap();
        thread::sleep(time::Duration::from_millis(interval * 1000));
        found_result = get_results_from_container(docker, env!("VECTOR_RESULT_PATH"), container_id)
            .await
            .unwrap(); //if there is a result file then stop the function
    }

    Ok(())
}

//this function just gives a few minutes to let the application run to generate some results
pub async fn test_application_volume(
    docker: &Docker,
    result_file: &str,
    tee_client_mode: Mode,
) -> Result<(), Box<dyn Error>> {
    write_to_log("===== Testing the application", "info").unwrap();

    //create directories and mounting the memory ram
    create_and_mount(vec![
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_RESULT_DIR")).to_string()
    ])
    .await?;

    let time_interval: u64 = env!("TEST_APPLICATION_TIME_INTERVAL").parse().unwrap();
    let tries_limit: u64 = env!("TEST_APPLICATION_ATTEMPTS_LIMIT").parse().unwrap();
    let mut tryes = 0;
    let mut existing = false;
    while !existing {
        existing = is_file_existing(&format!(
            "{}{}{}",
            env!("TEE_ROOT_DIR"),
            env!("TEE_DATA_DIR"),
            result_file
        ));
        tryes += 1;
        if tryes > tries_limit {
            destroy_environment(Some(docker), tee_client_mode.clone()).await?;
        }
        write_to_log("waiting 1 second", "info").unwrap();
        thread::sleep(time::Duration::from_millis(time_interval * 1000));
    }
    if existing {
        create_result_file(
            "result_file",
            &format!(
                "{}{}{}",
                env!("TEE_ROOT_DIR"),
                env!("TEE_DATA_DIR"),
                result_file
            ),
        )
        .await?;
    }

    Ok(())
}

//save the results from the vector-outflow and save it in a file
pub async fn get_results_from_container(
    docker: &Docker,
    file_path: &str,
    container_id: &str,
) -> Result<bool, Box<dyn Error>> {
    write_to_log("===== Download results from the container", "info").unwrap();

    let options = Some(DownloadFromContainerOptions { path: file_path });

    let stream = docker.download_from_container(container_id, options);
    tokio::pin!(stream);
    while let Some(result) = futures_util::StreamExt::next(&mut stream).await {
        match result {
            Ok(chunk) => {
                let mut file = fs::File::create(concat!(
                    env!("TEE_ROOT_DIR"),
                    env!("TEE_RESULT_DIR"),
                    env!("RESULT_FILE")
                ))?;
                std::io::Write::write_all(&mut file, &chunk).unwrap();
            },
            Err(err) => {
                write_to_log(
                    &format!("Error downloading the file from the container : {}", err),
                    "message",
                )
                .unwrap();
            },
        }
    }

    let existing = is_file_existing(concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_RESULT_DIR"),
        env!("RESULT_FILE")
    ));
    if existing {
        create_result_file(
            "result_file",
            concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_RESULT_DIR"),
                env!("RESULT_FILE")
            ),
        )
        .await
        .unwrap();
    }

    Ok(existing)
}

//create the propoerly name resut file in the result directory
pub async fn create_result_file(
    result_file_name: &str,
    result_file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let mut builder = Builder::new(
        File::create(concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_RESULT_DIR"),
            env!("RESULT_TMP_FILE")
        ))
        .unwrap(),
    );
    builder
        .append_file(
            env!("AMD_ATTESTATION_REPORT_FILE"),
            &mut File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("AMD_ATTESTATION_REPORT_FILE")
            ))
            .unwrap(),
        )
        .unwrap();
    builder
        .append_file(result_file_name, &mut File::open(result_file_path).unwrap())
        .unwrap();
    write_to_log("file found and saved correctly!", "message").unwrap();

    Ok(())
}

//this function destroy the containers, the image, the network umount the directories
pub async fn destroy_environment(
    docker: Option<&Docker>,
    tee_client_mode: Mode,
) -> Result<(), Box<dyn Error>> {
    write_to_log("===== Starting the client clean-up", "info").unwrap();

    //umount all the folders
    let _ = unmount(
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_APPLICATION_CERTS_DIR")
        ),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_CERTS_DIR"),
            env!("TEE_DATA_CERTS_DIR")
        ),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_CERTS_DIR")),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_APPLICATION_DIR")),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_DATA_DIR")),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_RESULT_DIR")),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR")),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("VECTOR_PIPELINE_DIR")),
        UnmountFlags::DETACH,
    );
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR")),
        UnmountFlags::FORCE,
    );

    //stop and remove the containers,network and image
    if tee_client_mode == Mode::Regular {
        match docker {
            Some(docker) => {
                remove_docker_containers(docker).await?;
                remove_docker_network(docker, env!("NETWORK_NAME")).await?;
                remove_docker_images(docker).await?;
            },
            None => eprintln!("no docker instantiated"),
        }
    }

    //remove directories
    let app_certs_dir = concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_CERTS_DIR"),
        env!("TEE_APPLICATION_CERTS_DIR")
    );
    let data_certs_dir = concat!(
        env!("TEE_ROOT_DIR"),
        env!("TEE_CERTS_DIR"),
        env!("TEE_DATA_CERTS_DIR")
    );
    let certs_dir = concat!(env!("TEE_ROOT_DIR"), env!("TEE_CERTS_DIR"));
    let data_dir = concat!(env!("TEE_ROOT_DIR"), env!("TEE_DATA_DIR"));
    let app_dir = concat!(env!("TEE_ROOT_DIR"), env!("TEE_APPLICATION_DIR"));
    let result_dir = concat!(env!("TEE_ROOT_DIR"), env!("TEE_RESULT_DIR"));
    let vector_dir = concat!(env!("TEE_ROOT_DIR"), env!("VECTOR_DIR"));
    let amd_attestation_dir = concat!(env!("TEE_ROOT_DIR"), env!("TEE_AMD_ATTESTATION_CLIENT_DIR"));
    let report_dir = concat!(env!("TEE_ROOT_DIR"), env!("TEE_REPORT_DIR"));
    if fs::metadata(app_certs_dir).is_ok() {
        fs::remove_dir_all(app_certs_dir)?;
    }
    if fs::metadata(data_certs_dir).is_ok() {
        fs::remove_dir_all(data_certs_dir)?;
    }
    if fs::metadata(certs_dir).is_ok() && tee_client_mode != Mode::BasicAttestation {
        fs::remove_dir_all(certs_dir)?;
    }
    if fs::metadata(data_dir).is_ok() {
        fs::remove_dir_all(data_dir)?;
    }
    if fs::metadata(app_dir).is_ok() {
        fs::remove_dir_all(app_dir)?;
    }
    if fs::metadata(result_dir).is_ok() {
        fs::remove_dir_all(result_dir)?;
    }
    if fs::metadata(vector_dir).is_ok() {
        fs::remove_dir_all(vector_dir)?;
    }
    if fs::metadata(amd_attestation_dir).is_ok() {
        fs::remove_dir_all(amd_attestation_dir)?;
    }
    if fs::metadata(report_dir).is_ok() {
        fs::remove_dir_all(report_dir)?;
    }

    write_to_log("END OF TEE CLIENT !!!", "info").unwrap();
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use crate::support_fn::{test_destroy, test_setup};

    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_create_directories() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // Define a temporary directory for testing
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        // Define a list of directories to create
        let directory_list = vec![
            (format!("{}/dir1", temp_path.to_string_lossy())),
            (format!("{}/dir2", temp_path.to_string_lossy())),
        ];

        // Call the function under test
        create_directories(directory_list.clone())?;

        // Check if directories were created
        for path in &directory_list {
            assert!(
                fs::metadata(path).is_ok(),
                "Directory {:?} was not created",
                path
            );
        }
        test_destroy().await?;
        Ok(())
    }
}
