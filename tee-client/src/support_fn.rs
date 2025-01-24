use chrono::Local;
use rand::{distributions::Uniform, Rng};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::process::Command;
use std::{error::Error, str};
use system_shutdown::shutdown;
extern crate sys_mount;
use crate::enum_names::CloudProvider;
use crate::wrappers::download_sev_binaries;
use log::info;
use std::os::unix::prelude::PermissionsExt;
use sys_mount::Mount;
use sys_mount::{unmount, UnmountFlags};

//
//this function generate a random numeric string used later for the network name
pub async fn check_if_file_exists(file_path: &str) -> Result<bool, Box<dyn Error>> {
    // Attempt to open the file
    if let Ok(mut file) = File::open(file_path) {
        // Check if the file is not empty
        let mut buffer = String::new();
        if let Ok(_) = file.read_to_string(&mut buffer) {
            let ret = !buffer.is_empty();
            return Ok(ret);
        }
    }
    // If any error occurs or the file is empty, return false
    Ok(false)
}

//
pub fn write_to_log(message: &str, mode: &str) -> std::io::Result<()> {
    if mode == "info" {
        info!("{}", message);
    } else if mode == "message" {
        println!("{}", message);
    }

    // Open the file in append mode, creating it if it doesn't exist
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(env!("TEE_LOG_DIR"))?;

    let current_time = Local::now();
    let formatted_time = current_time.format("%Y_%m_%d-%H_%M_%S").to_string();

    // Write the message followed by a newline character
    file.write_all(format!("{} ", formatted_time).as_bytes())?;
    file.write_all(message.as_bytes())?;
    file.write_all(b"\n")?;

    Ok(())
}

//this functions fetches the certificates
pub async fn curl_sev_guest(
    url: &str,
    local_file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _output = Command::new("curl")
        .arg("-fsSL")
        .arg(url)
        .arg("--output")
        .arg(local_file_path)
        .output()
        .map_err(|e| format!("failed to execute process: {}", e))?;

    let mut perms = fs::metadata(local_file_path)?.permissions();
    perms.set_mode(0o111);
    fs::set_permissions(local_file_path, perms)?;
    Ok(())
}

//get cloud provider
pub async fn get_cloud_provider(info: Value) -> Result<CloudProvider, Box<dyn std::error::Error>> {
    let cloud_provider_str = info
        .get("enclave")
        .unwrap()
        .get("cloud_provider")
        .unwrap()
        .as_str()
        .unwrap();

    if cloud_provider_str == "aws" {
        Ok(CloudProvider::Aws)
    } else if cloud_provider_str == "azure" {
        Ok(CloudProvider::Azure)
    } else if cloud_provider_str == "ovh" {
        Ok(CloudProvider::Ovh)
    } else {
        Err("Cloud provider is wrong!".into())
    }
}

//this function shutdown the VM
#[allow(dead_code)]
pub async fn shutdown_vm() -> Result<(), Box<dyn std::error::Error>> {
    shutdown().map_err(|err| format!("Failed to shut down: {}", err))?;
    write_to_log("Shutting down...", "message").unwrap();

    Ok(())
}

//check if a file is empty or not
pub fn is_file_existing(file_path: &str) -> bool {
    if let Ok(metadata) = fs::metadata(file_path) {
        return metadata.len() > 0;
    }
    false
}

//separate the folder path to the file name
pub fn s3_path_split_bucket(path: &str) -> Option<(&str, &str)> {
    let prefix = "s3://";

    if !path.starts_with(prefix) {
        return None;
    }

    let path = &path[prefix.len()..];
    let mut folders = path.splitn(2, '/');

    match (folders.next(), folders.next()) {
        (Some(first), Some(remaining)) => Some((first, remaining)),
        _ => None,
    }
}

//given a string, return the string without the occurence of the substring
pub fn remove_substring(main_string: &str, pattern: &str) -> String {
    if let Some(index) = main_string.find(pattern) {
        let mut result = main_string.to_string();
        result.replace_range(index..(index + pattern.len()), "");
        result
    } else {
        main_string.to_string()
    }
}

//split a string on the dot char
pub fn get_file_name(filename: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let mut parts = filename.split('.');

    if let (Some(part1), Some(_part2), None) = (parts.next(), parts.next(), parts.next()) {
        Ok(part1)
    } else {
        Ok(filename)
    }
}

//this function calculates the sha256 of the given var of bytes u8
pub fn calculate_content_sha256(payload: &[u8]) -> String {
    let hash = Sha256::digest(payload);
    hex::encode(&hash[..])
}

//this function generate a random numeric string used later for the network name
pub async fn generate_random_numeric_string() -> Result<String, Box<dyn Error>> {
    let s: String = rand::thread_rng()
        .sample_iter(&Uniform::new_inclusive(0, 9))
        .take(7)
        .map(|n| char::from_digit(n, 10).unwrap())
        .collect();
    Ok(s)
}

//this function mount a directory of the specifed size in ram memory
pub async fn mount(location: &str) -> Result<Mount, Box<dyn Error>> {
    write_to_log(&format!("===== Mounting {}", location), "info").unwrap();

    let mount_result = Mount::builder().fstype("tmpfs").mount(location, location)?;

    write_to_log("directory mounted correctly", "message").unwrap();
    Ok(mount_result)
}

//this function setup the environment for the tests
#[allow(dead_code)]
pub async fn test_setup(
    directory_list: Vec<&str>,
    download_certificates: bool,
) -> Result<(), Box<dyn Error>> {
    //get sudo privileges
    sudo::escalate_if_needed().unwrap();

    //create all directories
    for directory in directory_list {
        create_dir_all(directory)?;
    }

    if download_certificates {
        download_sev_binaries().await?;
    }

    Ok(())
}

//this function destroy the environment for the tests'
#[allow(dead_code)]
pub async fn test_destroy() -> Result<(), Box<dyn Error>> {
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
    let _ = unmount(
        concat!(env!("TEE_ROOT_DIR"), env!("TEE_SAMPLE_DIR")),
        UnmountFlags::FORCE,
    );

    //remove the directories
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
    if fs::metadata(certs_dir).is_ok() {
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::support_fn::{
        calculate_content_sha256, check_if_file_exists, generate_random_numeric_string,
        get_file_name, is_file_existing, mount, remove_substring, s3_path_split_bucket,
        test_destroy, test_setup,
    };
    use std::error::Error;
    use std::fs;
    extern crate sys_mount;
    use sys_mount::{unmount, UnmountFlags};

    #[tokio::test]
    async fn test_check_if_file_exists() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // Provide a file path for an existing and non-empty file
        let test_file_path = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_SAMPLE_DIR"),
            "existing_test_file"
        );
        std::fs::File::create(test_file_path).unwrap();
        let data = "Some data!";
        fs::write(test_file_path, data).expect("Unable to write file");

        // Provide a file path for a non-existing file
        let non_existing_file_path = "path/to/non/existing/file.txt";

        // Create a file and write some content to it for testing
        let content = "Hello, this is a test file!";
        let _ = tokio::fs::write(test_file_path, content).await;

        // Test for an existing and non-empty file
        let result = check_if_file_exists(test_file_path).await;
        assert!(result.unwrap());

        // Test for a non-existing file
        let result = check_if_file_exists(non_existing_file_path).await;
        assert!(!result.unwrap());

        // Clean up: Remove the test file
        let _ = tokio::fs::remove_file(test_file_path).await;

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_is_file_existing() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        //try with  existing file
        let test_file_path = concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_SAMPLE_DIR"),
            "existing_test_file"
        );
        std::fs::File::create(test_file_path).unwrap();
        let data = "Some data!";
        fs::write(test_file_path, data).expect("Unable to write file");

        assert!(is_file_existing(test_file_path));
        std::fs::remove_file(test_file_path).unwrap();

        //try with non existing file
        assert!(!is_file_existing("nonexistent_test_file"));
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_isolate_folders() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        //valid path
        let path = "s3://bucket-name/folder/file.txt";
        let result = s3_path_split_bucket(path);
        assert_eq!(result, Some(("bucket-name", "folder/file.txt")));

        //invalid path
        let path = "https://example.com/some-path";
        let result = s3_path_split_bucket(path);
        assert_eq!(result, None);

        //missing folder
        let path = "s3://file.txt";
        let result = s3_path_split_bucket(path);
        assert_eq!(result, None);
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_remove_substring() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // remove substring
        let main_string = "Hello, World!";
        let pattern = ", ";
        let result = remove_substring(main_string, pattern);
        assert_eq!(result, "HelloWorld!");

        //no occurence
        let main_string = "Hello, World!";
        let pattern = "foo";
        let result = remove_substring(main_string, pattern);
        assert_eq!(result, "Hello, World!");

        //empty
        let main_string = "";
        let pattern = "foo";
        let result = remove_substring(main_string, pattern);
        assert_eq!(result, "");
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_get_file_name() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // extension
        let filename = "example.txt";
        assert_eq!(get_file_name(filename).unwrap(), "example");

        // without extension
        let filename = "example";
        assert_eq!(get_file_name(filename).unwrap(), filename);

        //empty string
        let filename = "";
        assert_eq!(get_file_name(filename).unwrap(), filename);

        // multiple dots
        let filename = "example.file.txt";
        assert_eq!(get_file_name(filename).unwrap(), filename);
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_content_sha256() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        let payload: Vec<u8> = Vec::new();
        let result = calculate_content_sha256(&payload);
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let payload = b"Hello, world!";
        let result = calculate_content_sha256(payload);
        assert_eq!(
            result,
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_random_numeric_string() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;

        let result = generate_random_numeric_string().await;
        assert!(result.is_ok());
        let random_string = result.unwrap();
        assert_eq!(random_string.len(), 7);
        assert!(random_string.chars().all(|c| c.is_ascii_digit()));
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_mount_unmount() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;
        // create the directory
        let mount_location = concat!(env!("TEE_ROOT_DIR"), env!("TEE_TEST_DIR"));
        fs::create_dir_all(mount_location).unwrap();

        // Test mount
        let mount_result = mount(mount_location).await;
        assert!(mount_result.is_ok(), "Mounting should succeed");

        let unmount_result = unmount(mount_location, UnmountFlags::DETACH);

        assert!(unmount_result.is_ok(), "Unmounting should succeed");

        //delete the test path
        fs::remove_dir_all(mount_location).unwrap();
        test_destroy().await?;
        Ok(())
    }
}
