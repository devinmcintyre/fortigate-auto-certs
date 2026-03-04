#!/bin/bash

ROOT_DIR=/data/ssl
PASS="1234"


# Check for at least one argument (the domain)
if [ $# -lt 1 ]; then
    echo "Error: No domain specified"
    exit 1
fi

# Extract the domain and optional firewall arguments
domain=$1
firewall=${2:-""}

convert_cert() {
    # The first argument is both the site name and the firewall name
    local firewall=$1
    local domain=$2

    local directory_path="${ROOT_DIR}/${domain}"

    # Navigate to the directory
    cd $directory_path

    # Iterate over .pem files and convert them to .p12
    for file in ./*.pem; do
        if [[ -f $file && -s $file ]]; then
            echo "Non-null .pem file found - ${file}"
            PK12=$(basename "$file" .pem).p12
            openssl pkcs12 -export -inkey ${file} -in ${file} -out ${PK12} -passout "pass:${PASS}"
            echo "Coverted ${file} to .p12 format"
        else
            echo "No non-null .pem files exist in $(pwd)"
        fi
    done

    # Return to the ROOT_DIR
    cd $ROOT_DIR
}

push_cert() {
    # The first argument is the site/firewall name
    local firewall=$1
    local domain=$2

    # Construct the full directory path
    local directory_path="${ROOT_DIR}/${domain}"

    # Navigate to the directory
    cd $directory_path

    # Iterate over .p12 files and push them to the firewall
    for file in ./*.p12; do
        if [[ -f $file && -s $file ]]; then
            PK12=$(basename "$file")
            echo "Non-null .p12 file found - ${PK12}."
            echo "Pushing to IP Address ${FW_IPS[$firewall]} using API key ${API_KEYS[$firewall]}."
            echo "python3 /root/lets-encrypt-scripts/fortigateuploadcert.py ${FW_IPS[$firewall]} ${API_KEYS[$firewall]} $PK12 ${PASS} $PK12"
            python3 /root/lets-encrypt-scripts/fortigateuploadcert.py ${FW_IPS[$firewall]} ${API_KEYS[$firewall]} $PK12 ${PASS} $PK12
        else
            echo "No non-null .p12 was found in ${directory_path}";
        fi
    done

    # Return to the ROOT_DIR
    cd $ROOT_DIR
}

declare -A API_KEYS
API_KEYS[fortigate1]=fortigate_example_apikey_1
API_KEYS[fortigate2]=fortigate_example_apikey_2

declare -A FW_IPS
FW_IPS[fortigate1]=fortigate1.company.example
FW_IPS[fortigate2]=fortigate2.company.example

# Function to process a given site/firewall
firewall=$1
convert_cert "$firewall" "$domain"
push_cert "$firewall" "$domain"

echo $domain
echo $firewall