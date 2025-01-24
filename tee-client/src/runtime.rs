extern crate bollard;
use crate::support_fn::write_to_log;
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
};
use bollard::image::{ImportImageOptions, ListImagesOptions};
use bollard::image::RemoveImageOptions;
use bollard::models::HostConfig;
use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions, ListNetworksOptions};
use bollard::service::{EndpointSettings, PortBinding};
use bollard::Docker;
use futures_util::stream::StreamExt;
use log::error;
use serde_json::Value;
use std::collections::HashMap;
use std::default::Default;
use std::error::Error;
use std::process::Command;
use std::{thread, time};
use tokio::fs::File;
use tokio_util::codec;

//connecting to docker using default connection
pub async fn docker_connect() -> Result<Docker, Box<dyn Error>> {
    write_to_log("===== Connecting to docker", "info").unwrap();

    let docker = Docker::connect_with_socket_defaults().unwrap();
    write_to_log("succefully connected to docker", "message").unwrap();
    Ok(docker)
}

// this function will load the image in docker
pub async fn docker_load_image(docker: &Docker, image_file: &str) -> Result<(), Box<dyn Error>> {
    write_to_log(
        &format!("===== Loading image on docker : {}", image_file),
        "info",
    )
    .unwrap();
    let docker_clone = docker;
    use bollard::errors::Error;
    async move {
        let file = File::open(image_file).await.unwrap();

        let byte_stream = codec::FramedRead::new(file, codec::BytesCodec::new()).map(|r| {
            let bytes = r.unwrap().freeze();
            Ok::<_, Error>(bytes)
        });
        let body = hyper::Body::wrap_stream(byte_stream);
        let mut stream = docker_clone.import_image(
            ImportImageOptions {
                ..Default::default()
            },
            body,
            None,
        );
        stream.next().await;
    }
    .await;

    write_to_log("image loaded correctly", "message").unwrap();
    Ok(())
}

//run the applicatio container for application that uses volumes
pub async fn docker_run_container_volume(
    docker: &Docker,
    image_name: &str,
    command_length: usize,
    value_command: Vec<Value>,
    dataset_name: &str,
    result_file: &str,
    bind_folder: Vec<std::string::String>,
) -> Result<(), Box<dyn std::error::Error>> {
    write_to_log(
        &format!("===== Running the docker container for {}", image_name),
        "info",
    )
    .unwrap();

    let host_config = HostConfig {
        binds: Some(bind_folder),
        ..Default::default()
    };

    //here we change the command from Vec<Value> to Vec<&str>
    let mut str_command = Vec::new();
    let mut i = 0;
    let dataset_command = "/folder/".to_string() + dataset_name;
    let result_command = "/folder/".to_string() + result_file;

    while i < command_length {
        if value_command[i].as_str().unwrap().eq("KEYWORD_DATASET") {
            str_command.push(dataset_command.as_str());
        } else if value_command[i].as_str().unwrap().eq("KEYWORD_RESULT") {
            str_command.push(result_command.as_str());
        } else {
            str_command.push(value_command[i].as_str().unwrap());
        }
        i += 1;
    }

    let img_config = Config {
        image: Some(image_name),
        host_config: Some(host_config),
        cmd: Some(str_command),
        tty: Some(true),
        ..Default::default()
    };

    let id = docker
        .create_container::<&str, &str>(None, img_config)
        .await?
        .id;
    docker.start_container::<String>(&id, None).await?;

    write_to_log("docker container execution terminated correctly", "message").unwrap();
    Ok(())
}

//check if the docker image id actually loaded
pub async fn check_image_loaded(
    docker: &Docker,
    image_name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    write_to_log(
        &format!("===== Checking if the image {} is loaded", image_name),
        "info",
    )
    .unwrap();

    let time_interval: u64 = env!("DOCKER_LOAD_CHECK_INTERVAL").parse().unwrap();
    let tries_limit: u64 = env!("DOCKER_LOAD_IMAGE_ATTEMPTS_LIMIT").parse().unwrap();
    let mut count = 0;
    let mut image_loaded = false;
    while !image_loaded && count < tries_limit {
        match docker.inspect_image(image_name).await {
            Ok(_) => {
                image_loaded = true;
                write_to_log("The image is loaded", "message").unwrap();
            },
            Err(_err) => {
                write_to_log(
                    &format!("the image is not yet loaded, i will try again: n.{}", count),
                    "message",
                )
                .unwrap();
            },
        }
        thread::sleep(time::Duration::from_millis(time_interval * 1000));
        count += 1;
    }

    if count >= tries_limit {
        error!("ERROR!!! image loading failed");
    }

    Ok(image_loaded)
}

//This function remove a container from docker
pub async fn remove_docker_container(
    docker: &Docker,
    id: String,
) -> Result<String, Box<dyn std::error::Error>> {
    write_to_log(&format!("===== Removing the container {}", id), "info").unwrap();

    docker
        .remove_container(
            &id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await?;

    write_to_log("container removed correctly", "message").unwrap();
    Ok(id)
}

//This function remove the container
pub async fn remove_docker_containers(docker: &Docker) -> Result<(), Box<dyn std::error::Error>> {
    write_to_log("===== Removing all the containers", "info").unwrap();

    let mut filters = HashMap::new();
    filters.insert("status", vec!["created", "exited", "running"]);

    let options = Some(ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    });
    let container_list = docker.list_containers(options).await?;
    for container in container_list {
        remove_docker_container(docker, container.id.unwrap()).await?;
    }
    Ok(())
}

//This function remove all the images from docker
pub async fn remove_docker_images(
    docker: &Docker,
) -> Result<(), Box<dyn std::error::Error>> {
    write_to_log(&format!("===== Removing all the images"), "info").unwrap();

    let filters: HashMap<&str, Vec<&str>> = HashMap::new();
    let options = Some(ListImagesOptions{
    all: true,
    filters,
    ..Default::default()
    });

    let image_list = docker.list_images(options).await?;

    for image in image_list{
        write_to_log(&format!("removing the image: {}",image.id), "message").unwrap();
        remove_docker_image(docker, &image.id).await?;
    }

    Ok(())
}

//This function remove an image from docker
pub async fn remove_docker_image(
    docker: &Docker,
    image_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    write_to_log(&format!("===== Removing the image: {}", image_name), "info").unwrap();

    let remove_options = Some(RemoveImageOptions {
        //force: true,
        ..Default::default()
    });
    docker
        .remove_image(image_name, remove_options, None)
        .await?;

    Ok(())
}

//this function create a network with the specified name
pub async fn create_network(
    docker: &Docker,
    network_name: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    write_to_log(
        &format!("===== Creating the network {}", network_name),
        "info",
    )
    .unwrap();

    let config = CreateNetworkOptions {
        name: network_name,
        ..Default::default()
    };
    let network = docker.create_network(config).await?;

    write_to_log("network created correctly", "message").unwrap();
    Ok(network.id)
}

//this function pull a docker image from docker hub
pub async fn remove_docker_network(docker: &Docker, network_name: &str) -> Result<(), Box<dyn Error>> {
    let mut list_networks_filters = HashMap::new();
    list_networks_filters.insert("name", vec![network_name]);
    let config = ListNetworksOptions {
        filters: list_networks_filters,
    };
    let network_list = docker.list_networks(Some(config)).await?;

    for network in network_list {
        write_to_log("===== Removing the network", "info").unwrap();
        docker.remove_network(&(network.name.unwrap())).await?;
        write_to_log("network removed correctly", "message").unwrap();
    }

    Ok(())
}

//this function is used to run the application container for apps that uses http
pub async fn docker_run_container_http(
    docker: &Docker,
    container_name: &str,
    network_name: &str,
    image_name: &str,
    volume_directory_name: Option<Vec<std::string::String>>,
    env_variable_list: Option<Vec<&str>>,
    app_port: &str,
    tty: bool,
) -> Result<String, Box<dyn Error>> {
    write_to_log(
        &format!(
            "===== creating and running the container for the application :  {}",
            container_name
        ),
        "info",
    )
    .unwrap();

    let app_port_protocol = format!("{}/tcp", app_port);

    //ports settings declaration
    let mut exposed_ports: HashMap<&str, HashMap<(), ()>> = std::collections::HashMap::new();
    let port = std::collections::HashMap::new();
    exposed_ports.insert(&app_port_protocol, port);
    let mut final_port_bindings = HashMap::new();
    let global_port_bindings = vec![PortBinding {
        host_ip: Some("".to_string()),
        host_port: Some(app_port.to_string()),
    }];
    final_port_bindings.insert(app_port_protocol.to_owned(), Some(global_port_bindings));

    //ports setting implementation
    let host_config = HostConfig {
        binds: volume_directory_name,
        port_bindings: Some(final_port_bindings),
        network_mode: Some(network_name.to_string()),
        ..Default::default()
    };

    let config = Config {
        image: Some(image_name),
        env: env_variable_list,
        exposed_ports: Some(exposed_ports),
        host_config: Some(host_config),
        tty: Some(tty),
        ..Default::default()
    };

    let options = Some(CreateContainerOptions {
        name: container_name,
        platform: None,
    });

    let container = docker.create_container(options, config).await?;
    let network_config = ConnectNetworkOptions {
        container: container_name,
        endpoint_config: EndpointSettings {
            ..Default::default()
        },
    };
    docker.connect_network(network_name, network_config).await?;

    // Get the container details
    let container_info = docker.inspect_container(&container.id, None).await.unwrap();
    let network_settings = container_info.network_settings.unwrap();

    // Modify the network settings
    let mut modified_network_settings = network_settings.clone();
    let mut final_port_bindings = HashMap::new();

    let global_port_bindings = vec![
        PortBinding {
            host_ip: Some("0.0.0.0".to_string()),
            host_port: Some(app_port.to_owned()),
        },
        PortBinding {
            host_ip: Some("::".to_string()),
            host_port: Some(app_port.to_owned()),
        },
    ];
    final_port_bindings.insert(app_port_protocol, Some(global_port_bindings));
    modified_network_settings.ports = Some(final_port_bindings);

    //finally start the container
    docker
        .start_container::<String>(&container.id, None)
        .await?;

    write_to_log("container for the application created correctly", "message").unwrap();
    Ok(container.id)
}

//this function runs the two vector inflow/outflow
pub async fn docker_run_container_in_out_flow(
    docker: &Docker,
    container_name: &str,
    network_name: &str,
    image_name: &str,
    volume_directory_name: Option<Vec<std::string::String>>,
    env_variable_list: Option<Vec<&str>>,
) -> Result<String, Box<dyn Error>> {
    write_to_log(
        &format!(
            "===== creating and running the container {}",
            container_name
        ),
        "info",
    )
    .unwrap();

    let host_config = HostConfig {
        binds: volume_directory_name,
        port_bindings: None,
        network_mode: Some(network_name.to_string()),
        ..Default::default()
    };

    let config = Config {
        image: Some(image_name),
        env: env_variable_list,
        exposed_ports: None,
        host_config: Some(host_config),
        tty: Some(false),
        ..Default::default()
    };

    let options = Some(CreateContainerOptions {
        name: container_name,
        platform: None,
    });

    let container = docker.create_container(options, config).await?;

    let config = ConnectNetworkOptions {
        container: container_name,
        endpoint_config: EndpointSettings {
            ..Default::default()
        },
    };

    docker.connect_network(network_name, config).await?;
    docker
        .start_container::<String>(&container.id, None)
        .await?;

    write_to_log("container created correctly", "message").unwrap();
    Ok(container.id)
}

//
pub async fn docker_pull(image_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _output = Command::new("docker")
        .arg("pull")
        .arg(image_name)
        .output()
        .map_err(|e| format!("failed to execute process: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use bollard::container::{Config, CreateContainerOptions};

    use crate::{
        runtime::{
            check_image_loaded, create_network, docker_connect, docker_load_image,
            remove_docker_container, remove_docker_image, remove_docker_network,
        },
        support_fn::{test_destroy, test_setup, write_to_log},
    };
    use std::{error::Error, fs, process::Command};

    #[tokio::test]
    async fn test_load_check_remove_image() -> Result<(), Box<dyn Error>> {
        test_setup(
            vec![concat!(env!("TEE_ROOT_DIR"), env!("TEE_SAMPLE_DIR"))],
            false,
        )
        .await?;
        //connect to docker
        let docker = docker_connect().await.unwrap();
        let image_name = "hello-world";
        let image_file = "hello-world-test.tar";

        let image_file_path = format!(
            "{}{}{}",
            env!("TEE_ROOT_DIR"),
            env!("TEE_SAMPLE_DIR"),
            image_file
        );

        //first i download an hello world image
        let _output = Command::new("docker")
            .arg("pull")
            .arg(image_name)
            .output()
            .map_err(|e| format!("failed to execute process: {}", e))?;

        let _output = Command::new("docker")
            .arg("save")
            .arg("--output")
            .arg(image_file)
            .arg(image_name)
            .output()
            .map_err(|e| format!("failed to execute process: {}", e))?;

        let _output = Command::new("mv")
            .arg(image_file)
            .arg(&image_file_path)
            .output()
            .map_err(|e| format!("failed to execute process: {}", e))?;

        match remove_docker_image(&docker, image_name).await {
            Ok(_) => {
                write_to_log("image removed correctly", "message").unwrap();
            },
            Err(_) => {
                write_to_log("the image was not existing", "message").unwrap();
            },
        };

        //then i try to load it on docker
        let result = docker_load_image(&docker, &image_file_path).await;
        assert!(result.is_ok());
        let result = check_image_loaded(&docker, image_name).await;
        assert!(result.is_ok());
        match remove_docker_image(&docker, image_name).await {
            Ok(_) => {
                write_to_log("image removed correctly", "message").unwrap();
            },
            Err(_) => {
                write_to_log("the image was not existing", "message").unwrap();
            },
        };

        //delete the image.tar file
        fs::remove_file(image_file_path)?;
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_create_remove_network() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;

        // test create network
        let docker = docker_connect().await.unwrap();
        let network_name = "test_network";

        let result = create_network(&docker, network_name).await;

        assert!(result.is_ok());
        let network_id = result.unwrap();
        assert!(network_id.is_some(), "Expected Some value for network ID");

        //test remove network
        let result = remove_docker_network(&docker, network_name).await;
        assert!(result.is_ok());
        test_destroy().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_remove_container() -> Result<(), Box<dyn Error>> {
        test_setup(vec![], false).await?;

        let docker = docker_connect().await.unwrap();
        let image_name = "hello-world";

        //first download an test image
        let _output = Command::new("docker")
            .arg("pull")
            .arg(image_name)
            .output()
            .map_err(|e| format!("failed to execute process: {}", e))?;

        let options = Some(CreateContainerOptions {
            name: "my-new-container",
            platform: None,
        });

        let config = Config {
            image: Some(image_name),
            cmd: Some(vec!["/hello"]),
            ..Default::default()
        };

        let container = docker.create_container(options, config).await.unwrap();
        docker
            .start_container::<String>(&container.id, None)
            .await?;

        let result = remove_docker_container(&docker, container.id).await;
        assert!(result.is_ok());

        remove_docker_image(&docker, image_name).await.unwrap();
        test_destroy().await?;
        Ok(())
    }
}
