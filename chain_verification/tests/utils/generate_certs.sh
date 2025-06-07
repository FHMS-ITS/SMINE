#!/bin/bash

# Create directories to organize the certificates
mkdir -p certs/rootA certs/intermediateA certs/intermediateA_alt certs/leafA
mkdir -p certs/rootB certs/leafB
mkdir -p certs/tmp

# Function to generate a root certificate
generate_root_cert() {
  local NAME=$1
  local DIR=$2

  # Generate private key
  openssl genrsa -out $DIR/$NAME.key.pem 2048

  # Generate self-signed root certificate
  openssl req -x509 -new -nodes -key $DIR/$NAME.key.pem \
    -sha256 -days 1024 \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Org Unit/CN=$NAME Root CA" \
    -out $DIR/$NAME.cert.pem
}

# Function to generate an intermediate certificate signed by a root
generate_intermediate_cert() {
  local NAME=$1
  local DIR=$2
  local ROOT_NAME=$3
  local ROOT_DIR=$4
  local ADD_KEYUSAGE=$5  # New boolean parameter: "true" or "false"

  # Generate private key
  openssl genrsa -out "$DIR/$NAME.key.pem" 2048

  # Generate CSR
  openssl req -new -key "$DIR/$NAME.key.pem" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Org Unit/CN=$NAME Intermediate CA" \
    -out "$DIR/$NAME.csr.pem"

  # If ADD_KEYUSAGE is true, create an extensions file with keyUsage
  if [ "$ADD_KEYUSAGE" = true ]; then
    # Create a temporary extensions file
    EXT_FILE="$DIR/$NAME.ext"
    # Add the keyUsage extension
    cat > "$EXT_FILE" << EOF
basicConstraints=CA:TRUE
keyUsage = digitalSignature, keyCertSign, cRLSign
EOF
    EXT_OPTION="-extfile $EXT_FILE"
  else
    EXT_OPTION=""
  fi

  # Sign CSR with Root CA to get intermediate certificate
  openssl x509 -req -in "$DIR/$NAME.csr.pem" \
    -CA "$ROOT_DIR/$ROOT_NAME.cert.pem" -CAkey "$ROOT_DIR/$ROOT_NAME.key.pem" \
    -CAcreateserial -out "$DIR/$NAME.cert.pem" -days 500 -sha256 $EXT_OPTION

  # Clean up the extensions file if it was created
  if [ "$ADD_KEYUSAGE" = true ]; then
    rm "$EXT_FILE"
  fi
}

# Function to generate a leaf certificate signed by an intermediate
generate_leaf_cert() {
  local NAME=$1
  local DIR=$2
  local INTERMEDIATE_NAME=$3
  local INTERMEDIATE_DIR=$4

  # Generate private key
  openssl genrsa -out $DIR/$NAME.key.pem 2048

  # Generate CSR
  openssl req -new -key $DIR/$NAME.key.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Org Unit/CN=$NAME Leaf Cert" \
    -out $DIR/$NAME.csr.pem

  # Sign CSR with Intermediate CA to get leaf certificate
  openssl x509 -req -in $DIR/$NAME.csr.pem \
    -CA $INTERMEDIATE_DIR/$INTERMEDIATE_NAME.cert.pem -CAkey $INTERMEDIATE_DIR/$INTERMEDIATE_NAME.key.pem \
    -CAcreateserial -out $DIR/$NAME.cert.pem -days 400 -sha256
}

# Generate Root Certificate A
generate_root_cert "rootA" "certs/rootA"

# Generate Intermediate A signed by Root A
generate_intermediate_cert "intermediateA" "certs/intermediateA" "rootA" "certs/rootA" false

# Generate Intermediate A (same subject, different fingerprint) signed by Root A
# To have a different fingerprint, we can use a different key or add an extension
generate_intermediate_cert "intermediateA" "certs/intermediateA_alt" "rootA" "certs/rootA" true

# Generate Leaf Certificate signed by Intermediate A
generate_leaf_cert "leafA" "certs/leafA" "intermediateA" "certs/intermediateA"

# Generate Root Certificate B
generate_root_cert "rootB" "certs/rootB"

# Generate Leaf Certificate B signed by Root B
generate_leaf_cert "leafB" "certs/leafB" "rootB" "certs/rootB"

# Clean up temporary files
rm -rf certs/tmp
