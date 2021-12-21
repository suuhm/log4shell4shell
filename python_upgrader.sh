#!/bin/bash

VERS=$1
echo "Install/Upgrade Python $VERS Helper - BY suuhmer (C) 2021"
echo "Mainly tested and used on Debian/Ubuntu Linux OS"
echo

if [ -z $VERS ]
  echo "Usage $0 VERSION (See full list with: $0 --list-versions)"
fi

if [ "$1" == "--list-versions"]; then
  echo -e "List of actual python versions available:\n"
  curl -sL https://www.python.org/downloads/ | grep -E "Python\ [1-3]\.[0-9].[0.9]" | sed -r 's/.*\ ([0-9].*[0-9]).*/\1/g'
fi

apt update && apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev

echo && sleep 3
echo

wget https://www.python.org/ftp/python/$VERS/Python-$VERS.tgz
tar xvf Python-$VERS.tgz
cd Python-$VERS
./configure --enable-optimizations --enable-shared
make -j8 && make altinstall

echo && sleep 2
echo

ldconfig

echo "Optional Alternatives change:"
echo

# update-alternatives --install /usr/bin/python python /usr/local/bin/python3.7 50
update-alternatives --config python

echo -e "\nDONE! exit.."
exit 0
