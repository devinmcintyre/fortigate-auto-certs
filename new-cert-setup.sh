#!/bin/bash

# Function to create directory structure
create_directory_structure() {
    local dns_zone_name=$1
    local site_name=$2
    local directory_path="/data/ssl/$dns_zone_name"

    mkdir -p "$directory_path"
    echo "Directory created at: $directory_path"
}

# Function to print the acme.sh command
print_acme_command() {
    local dns_zone_name=$1
    local site_name=$2

    echo "Command to run:"
    echo "acme.sh --issue --dns dns_azure -d $dns_zone_name -d *.$dns_zone_name --post-hook \"cat /root/.acme.sh/${dns_zone_name}_ecc/${dns_zone_name}.key /root/.acme.sh/${dns_zone_name}_ecc/fullchain.cer > /data/ssl/$dns_zone_name/$dns_zone_name.pem; bash /root/lets-encrypt-scripts/certmanager.sh $dns_zone_name $site_name\""
}

# Check if site name and DNS zone name are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <dns-zone-name> <site-name>"
    exit 1
fi

dns_zone_name=$1
site_name=$2

# Create the directory structure
create_directory_structure "$dns_zone_name" "$site_name"
# Print the acme.sh command
print_acme_command "$dns_zone_name" "$site_name"