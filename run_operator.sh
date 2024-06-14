#!/bin/bash

# Copy the script/.env file to the container if it exists
if [ -f "script/.env" ]; then
    # Make the /etc/secrets directory if it doesn't exist
    mkdir -p ./etc/secrets
    # If this fails, exit the script
    cp script/.env ./etc/secrets/.env || exit 1
fi

docker run -d --name turing-sepolia-operator sp1-vectorx-operator
