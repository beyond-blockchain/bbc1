#!/bin/bash

if [[ ! -f ../venv/bin/activate ]]; then
  echo 'Run "starter.sh install" to prepare the environment'
  exit 1
fi

if [ $# -ne 1 -a $# -ne 2 ]; then
  echo "Usage: $0 [register|show_all|print]"
  exit 1
fi

. ../venv/bin/activate


case $1 in
  register)
    python register_a_transaction.py -i ID_FILE
    ;;

  show_all)
    python show_transactions.py -i ID_FILE
    ;;

  print)
    python print_transaction.py -i ID_FILE -t $2
    ;;

  *)
    echo "Usage: $0 [register|show_all|print]"
    exit 1
esac
