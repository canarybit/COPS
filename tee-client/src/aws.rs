use crate::{
    enum_names::Owner,
    report::{generate_evidence_report_binary, generate_evidence_report_plaintext_file, generate_signature_sig},
    support_fn::write_to_log,
};
use std::{
    error::Error,
    fs::{copy, remove_file, File},
};
use tar::Builder;

//
pub async fn attest_aws(owner: Owner, csr: bool) -> Result<(), Box<dyn Error>> {
    write_to_log("The VM is AWS", "message").unwrap();

    collect_evidence_aws(&owner).await?;
    generate_report_aws(&owner, csr).await?;
    cleanup_files_aws().await?;

    Ok(())
}

//
pub async fn collect_evidence_aws(owner: &Owner) -> Result<(), Box<dyn Error>> {
    generate_evidence_report_binary(owner).await?;
    generate_evidence_report_plaintext_file().await?;
    Ok(())
}

//
pub async fn generate_report_aws(owner: &Owner, csr: bool) -> Result<(), Box<dyn Error>> {
    copy(
        env!("AWS_VLEK"),
        concat!(
            env!("TEE_ROOT_DIR"),
            env!("TEE_REPORT_DIR"),
            env!("AWS_VLEK")
        ),
    )
    .expect("AWS-specific VLEK certificate copy failed");

    generate_signature_sig(owner).await?;
    build_aws_report_file(owner, csr).await?;

    Ok(())
}

//
pub async fn build_aws_report_file(owner: &Owner, csr: bool) -> Result<(), Box<dyn Error>> {
    //Make the evidence_archive
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
            env!("AWS_VLEK"),
            &mut File::open(concat!(
                env!("TEE_ROOT_DIR"),
                env!("TEE_REPORT_DIR"),
                env!("AWS_VLEK")
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
    .expect("Failed to copy evidence archive");

    Ok(())
}

//
pub async fn cleanup_files_aws() -> Result<(), Box<dyn Error>> {
    remove_file(env!("TEE_ATTESTATION_REPORT_FILE"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        aws::attest_aws,
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
    async fn test_attest_aws_csr() -> Result<(), Box<dyn Error>> {
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

        if cloud_provider == CloudProvider::Aws {
            generate_tee_client_certificate(&info, Owner::Application).await?;
            generate_extended_claims_file(info.clone(), Mode::Regular).await?;

            //test with csr
            let response = attest_aws(Owner::Application, true).await;
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
    async fn test_attest_aws_no_csr() -> Result<(), Box<dyn Error>> {
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

        if cloud_provider == CloudProvider::Aws {
            generate_tee_client_certificate(&info, Owner::Application).await?;
            generate_extended_claims_file(info.clone(), Mode::AttestationOnly).await?;

            //test without the csr
            let response = attest_aws(Owner::Application, false).await;
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
    async fn test_attest_aws_no_owner() -> Result<(), Box<dyn Error>> {
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

        if cloud_provider == CloudProvider::Aws {
            generate_extended_claims_file(info.clone(), Mode::BasicAttestation).await?;

            //test without the owner
            generate_tee_client_certificate(&info, Owner::Empty).await?;
            let response = attest_aws(Owner::Empty, false).await;
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
