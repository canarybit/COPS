use crate::{
    enum_names::Owner,
    report::{generate_evidence_report_plaintext_file, generate_signature_sig},
    support_fn::write_to_log,
};
use std::{
    error::Error,
    fs::{self, copy, remove_file, File},
    io::Write,
    process::Command,
};
use tar::Builder;

//
pub async fn attest_azure(owner: Owner, csr: bool) -> Result<(), Box<dyn Error>> {
    write_to_log("The VM is AZURE", "message").unwrap();

    collect_evidence_azure().await?;
    generate_report_azure(&owner, csr).await?;
    cleanup_files_azure().await?;

    Ok(())
}

//
pub async fn collect_evidence_azure() -> Result<(), Box<dyn Error>> {
    generate_azure_report_bin().await?;
    generate_evidence_report_plaintext_file().await?;

    Ok(())
}

//
pub async fn generate_report_azure(owner: &Owner, csr: bool) -> Result<(), Box<dyn Error>> {
    generate_signature_sig(owner).await?;
    build_azure_report_file(owner, csr).await?;

    Ok(())
}

//
pub async fn build_azure_report_file(owner: &Owner, csr: bool) -> Result<(), Box<dyn Error>> {
    let filer = File::create(env!("TEE_ATTESTATION_REPORT_FILE")).unwrap();
    let mut evidence_archive = Builder::new(filer);

    //Append the files to the evidence archive
    evidence_archive
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
    evidence_archive
        .append_file(
            env!("AMD_ATTESTATION_BIN_FILE"),
            &mut File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("AMD_ATTESTATION_BIN_FILE")
            ))
            .unwrap(),
        )
        .unwrap();
    evidence_archive
        .append_file(
            env!("AMD_CHAIN_VCEK_PEM"),
            &mut File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("AMD_CHAIN_VCEK_PEM")
            ))
            .unwrap(),
        )
        .unwrap();
    evidence_archive
        .append_file(
            env!("ENCLAVE_ID"),
            &mut File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("ENCLAVE_ID")
            ))
            .unwrap(),
        )
        .unwrap();
    evidence_archive
        .append_file(
            env!("SIGNATURE_SIG"),
            &mut File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("SIGNATURE_SIG")
            ))
            .unwrap(),
        )
        .unwrap();

    match owner {
        Owner::Application => {
            evidence_archive
                .append_file(
                    env!("TEE_APPLICATION_PUBLIC_KEY_FILE"),
                    &mut File::open(
                        env!("TEE_ROOT_DIR").to_owned()
                            + env!("TEE_CERTS_DIR")
                            + env!("TEE_APPLICATION_CERTS_DIR")
                            + env!("TEE_APPLICATION_PUBLIC_KEY_FILE"),
                    )
                    .unwrap(),
                )
                .unwrap();
            if csr {
                evidence_archive
                    .append_file(
                        env!("TEE_APPLICATION_CSR_FILE"),
                        &mut File::open(
                            env!("TEE_ROOT_DIR").to_owned()
                                + env!("TEE_REPORT_DIR")
                                + env!("TEE_APPLICATION_CSR_FILE"),
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
        },
        Owner::Dataset => {
            evidence_archive
                .append_file(
                    env!("TEE_DATA_PUBLIC_KEY_FILE"),
                    &mut File::open(
                        env!("TEE_ROOT_DIR").to_owned()
                            + env!("TEE_CERTS_DIR")
                            + env!("TEE_DATA_CERTS_DIR")
                            + env!("TEE_DATA_PUBLIC_KEY_FILE"),
                    )
                    .unwrap(),
                )
                .unwrap();
            if csr {
                evidence_archive
                    .append_file(
                        env!("TEE_DATA_CSR_FILE"),
                        &mut File::open(
                            env!("TEE_ROOT_DIR").to_owned()
                                + env!("TEE_REPORT_DIR")
                                + env!("TEE_DATA_CSR_FILE"),
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
        },
        Owner::Empty => {
            evidence_archive
                .append_file(
                    env!("TEE_DATA_PUBLIC_KEY_FILE"),
                    &mut File::open(
                        env!("TEE_ROOT_DIR").to_owned()
                            + env!("TEE_CERTS_DIR")
                            + env!("TEE_PUBLIC_KEY_FILE"),
                    )
                    .unwrap(),
                )
                .unwrap();
        },
    }

    copy(
        env!("TEE_ATTESTATION_REPORT_FILE"),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("TEE_ATTESTATION_REPORT_FILE")
        ),
    )
    .expect("evidence archive copy failed");
    remove_file(env!("TEE_ATTESTATION_REPORT_FILE")).unwrap();

    Ok(())
}

//
pub async fn generate_azure_report_bin() -> Result<(), Box<dyn Error>> {
    let res = Command::new("curl")
        .arg("-H")
        .arg("Metadata:true")
        .arg("http://169.254.169.254/metadata/THIM/amd/certification")
        .output()
        .map_err(|e| format!("failed to execute process: {}", e))?;

    let vcek_content = String::from_utf8(res.stdout).unwrap();
    let mut data_file = File::create(env!("AMD_CHAIN_VCEK")).expect("creation failed");
    data_file
        .write_all(vcek_content.as_bytes())
        .expect("write failed");

    let _output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat ./{} | jq -r '.vcekCert , .certificateChain' > ./{}",
            env!("AMD_CHAIN_VCEK"),
            env!("AMD_CHAIN_VCEK_PEM")
        ))
        .output();

    let _output2 = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "tpm2_nvread -C o 0x01400001 > ./{}",
            env!("AMD_ATTESTATION_SNP_REPORT_FILE")
        ))
        .output();

    let _output3 = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "dd skip=32 bs=1 count=1184 if=./{} of=./{}",
            env!("AMD_ATTESTATION_SNP_REPORT_FILE"),
            env!("AMD_ATTESTATION_BIN_FILE")
        ))
        .output();

    //Move them to the report folder
    fs::copy(
        env!("AMD_CHAIN_VCEK_PEM"),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("AMD_CHAIN_VCEK_PEM")
        ),
    )?;
    fs::copy(
        env!("AMD_ATTESTATION_BIN_FILE"),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("AMD_ATTESTATION_BIN_FILE")
        ),
    )?;

    Ok(())
}

//
pub async fn cleanup_files_azure() -> Result<(), Box<dyn Error>> {
    fs::remove_file(env!("AMD_CHAIN_VCEK")).unwrap();
    fs::remove_file(env!("AMD_ATTESTATION_SNP_REPORT_FILE")).unwrap();
    remove_file(env!("AMD_ATTESTATION_BIN_FILE"))?;
    remove_file(env!("AMD_CHAIN_VCEK_PEM"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        azure::attest_azure,
        credentials::{generate_tee_client_certificate, get_collaboration_info_data},
        enum_names::{CloudProvider, Mode, Owner},
        report::generate_extended_claims_file,
        support_fn::{get_cloud_provider, test_destroy, test_setup, write_to_log},
    };
    use std::{
        error::Error,
        fs::{self, remove_file},
    };

    #[tokio::test]
    async fn test_attest_azure_csr() -> Result<(), Box<dyn Error>> {
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

        let cloud_provider = get_cloud_provider(info.clone()).await?;

        if cloud_provider == CloudProvider::Azure {
            generate_tee_client_certificate(&info, Owner::Application).await?;
            generate_extended_claims_file(info.clone(), Mode::Regular).await?;

            //test with csr
            let response = attest_azure(Owner::Application, true).await;
            assert!(response.is_ok());
            match fs::metadata(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("TEE_ATTESTATION_REPORT_FILE")
            )) {
                Ok(_) => write_to_log("File exists!", "message").unwrap(),
                Err(_) => write_to_log("File does not exist!", "message").unwrap(),
            }
        }

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_attest_azure_no_csr() -> Result<(), Box<dyn Error>> {
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

        let cloud_provider = get_cloud_provider(info.clone()).await?;

        if cloud_provider == CloudProvider::Azure {
            generate_tee_client_certificate(&info, Owner::Application).await?;
            generate_extended_claims_file(info.clone(), Mode::AttestationOnly).await?;

            //test without the csr
            let response = attest_azure(Owner::Application, false).await;
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
        }

        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_attest_azure_no_owner() -> Result<(), Box<dyn Error>> {
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

        let cloud_provider = get_cloud_provider(info.clone()).await?;

        if cloud_provider == CloudProvider::Azure {
            generate_extended_claims_file(info.clone(), Mode::BasicAttestation).await?;

            //test without the owner
            generate_tee_client_certificate(&info, Owner::Empty).await?;
            let response = attest_azure(Owner::Empty, false).await;
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
        }

        test_destroy().await?;
        Ok(())
    }
}
