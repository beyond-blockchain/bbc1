Run a bbc_core on a docker container
================
This directory includes Dockerfiles and utility to create and execute a docker container that runs bbc_core.

## Utility script
docker-bbc1.sh is a utility to control docker container. You can find the usege of it by the command without any arguments (```./docker-bbc1.sh```).

* gitbuild
    - build docker container with BBc-1 sources
* pipbuild
    - build docker container with pip installation of bbc_core and so on
* gitbuild_v6, pipbuild_v6
    - build docker container with enabling IPv6 option
* start
    - start the created docker whose name is bbc1
* stop
    - stop the docker container
* restart
    - stop and start the docker container again
* rm
    - remove the docker container
* shell
    - log in to the container by attaching it with bash


## Base distribution
The Dockerfiles build Ubuntu 17.04 based container with python3 and virtualenv. The entrypoint.sh will be copied in the container, so do not delete it. In the created container, bbc_core runs by root. You can log in to the container by either ssh or attaching to the docker container. *Note that the ssh port on the host is 10022 by default.*

## BBc-1 installation
There are two Dockerfiles. One of them copies BBc-1 sources (the parent directory of here) in /root/bbc1/ of the container. In the other one, bbc_core and other tools are installed by pip. In both cases, bbc_core.py is automatically invoked when the container starts.

## Working directory
The working directory on the container is /root/.bbc1/, and the directory is mounted on data/.bbc1 on the host.

## Port configuration
BBc-1 uses two port numbers 9000 and 6641 of both TCP and UDP by default. Port 9000 is for communication between core and app. Port 6641 is for communication among bbc_cores to form P2P topologies.

The container is configured to expose those ports to the same port numbers of the host. If you want to run multiple BBc-1 containers on a single host, you need to change the ports to expose on the host (e.g., 6641 -> 6641 and 9000 -> 9001).
