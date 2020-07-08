#!/bin/bash

set -v 

echo 'Installing bandit'
#pip install --user bandit
if [ -x "$(command -v pip3)" ]; then
    pip3 install bandit
else
    pip install --user bandit
fi


echo 'Running Bandit tests'
bandit -r --ini .bandit -f json -o banditResult.json .

echo 'Results:'
python bandit/banditParser.py -o banditResult.json -i bandit.ignore
