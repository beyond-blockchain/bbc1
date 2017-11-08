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
	    cd .. && git archive-all bbc1.tar.gz && cd docker
	    mv ../bbc1.tar.gz .
	    docker build -t ${CONTAINER_NAME} -f Dockerfile_git .
	    rm requirements.txt bbc1.tar.gz
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
