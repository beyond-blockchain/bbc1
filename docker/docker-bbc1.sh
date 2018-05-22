#!/bin/bash

TIMEZONE=Asia/Tokyo

IMAGE_NAME=bbc1
CONTAINER_NAME=bbc1
SSH_PORT=10022
CORE_PORT=9000
P2PNW_PORT=6641


case $1 in
    start)
        docker run --name ${CONTAINER_NAME} -d -v ${PWD}/data/.bbc1:/root/.bbc1 -p ${SSH_PORT}:22 -p ${CORE_PORT}:9000 -p ${P2PNW_PORT}:6641 -e TZ=${TIMEZONE} ${IMAGE_NAME}
        ;;

    stop)
        docker stop ${CONTAINER_NAME}
        ;;

    restart)
        docker restart ${CONTAINER_NAME}
        ;;

    rm)
        docker rm ${CONTAINER_NAME}
        ;;

    shell)
        docker exec -it ${CONTAINER_NAME} /bin/bash
        ;;

    gitbuild)
        cp ../requirements.txt .
        cd ..
        git archive --prefix="bbc1/" HEAD > docker/bbc1.tar
        mkdir libs/openssl
        cd libs/openssl/
        git archive --prefix="bbc1/libs/openssl/" HEAD > ../../docker/sb1.tar
        cd ../../docker
        tar -rf bbc1.tar @sb1.tar
        gzip bbc1.tar
        docker build -t ${CONTAINER_NAME} -f Dockerfile_git .
        rm requirements.txt bbc1.tar.gz sb1.tar
        ;;

    pipbuild)
        cp ../requirements.txt .
        docker build -t ${CONTAINER_NAME} -f Dockerfile_pip .
        rm requirements.txt
        ;;

    *)
        echo "$0 [start|stop|restart|rm|shell|gitbuild|pipbuild]"
        echo
        ;;
esac
