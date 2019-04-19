#!/bin/bash


COMMAND=$1
ARG=$2


case ${COMMAND} in
  install)
    echo "# Prepare a python3 virtual environment and install modules"
    python3 -mvenv venv
    . venv/bin/activate
    pip install -r requirements.txt
    ;;

  clean)
    echo "# Clean up the BBc-1 working directory"
    rm -rf ./.bbc1
    rm -f DOMAIN_ID
    ;;

  setup)
    echo "# Setup a domain"
    . venv/bin/activate
    bbc_core.py -w .bbc1 --no_nodekey -d > /dev/null 2>&1
    sleep 1
    DOMAIN_ID=`id_create.py -s test_domain_seed`
    echo " -- setup domain_id=${DOMAIN_ID}"
    echo "${DOMAIN_ID}" > DOMAIN_ID
    bbc_domain_update.py -a -d ${DOMAIN_ID}
    bbc_core.py -k
    ;;

  core)
    echo "# Start bbc_core in background"
    . venv/bin/activate
    bbc_core.py -w .bbc1 --no_nodekey -d > /dev/null 2>&1
    ;;

  create)
    if [[ ${ARG} == "" ]]; then
      echo "Usage: $0 create [username]"
      exit
    fi
    echo "# Create a user: ${ARG}"
    mkdir ${ARG}
    [[ $? -gt 0 ]] && exit
    cp scripts/* ${ARG}/
    cd ${ARG}
    echo "  -- create key pair for user: ${ARG}"
    python create_userid_keypair.py -u ${ARG}
    ;;

  remove)
    if [[ ${ARG} == "" ]]; then
      echo "Usage: $0 remove [username]"
      exit
    fi
    echo "# Remove user: ${ARG}"
    if [[ -f ${ARG}/ID_FILE ]]; then
      rm -rf ${ARG}
      echo "  -- Removed!"
    fi
    ;;

  run)
    cd ${ARG}
    bash run_script.sh register
    ;;

  show)
    cd ${ARG}
    bash run_script.sh show_all
    ;;

  kill)
    echo "# Kill bbc_core"
    . venv/bin/activate
    bbc_core.py -k
    ;;

  *)
    echo "Usage: $0 [install|setup]"
    ;;
esac
