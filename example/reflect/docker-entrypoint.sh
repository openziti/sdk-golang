#!/usr/bin/env bash

set -x -e -u -o pipefail

# the default behavior of this entrypoint script is to run reflect server that
# was installed during docker build in /go/bin/reflect. This assumes
# ${APP_HOME}/${ZITI_SDK_CONFIG} is a Ziti identity config JSON file.  
#
# the alternative behavior to build from source is invoked when the source dir
# is present, and it is assumed that ${REFLECT_SRC_DIR}/${ZITI_SDK_CONFIG} is a
# Ziti identity config JSON file.  
REFLECT_SRC_DIR="${APP_HOME}/example/reflect"
if [[ -d "${REFLECT_SRC_DIR}" ]]; then
#    go build -mod=readonly -o "${REFLECT_SRC_DIR}" "${REFLECT_SRC_DIR}"
    go build -o "${REFLECT_SRC_DIR}" "${REFLECT_SRC_DIR}"
    REFLECT_BIN="${REFLECT_SRC_DIR}/reflect"
    IDENTITY_FILE="${REFLECT_SRC_DIR}/${ZITI_SDK_CONFIG}"
    echo "DEBUG: REFLECT_SRC_DIR=${REFLECT_SRC_DIR}"; ls -lAh "${REFLECT_SRC_DIR}"
else
    REFLECT_BIN=$(which reflect) # installed in Dockerfile
    IDENTITY_FILE="${APP_HOME}/${ZITI_SDK_CONFIG}"
fi

echo "DEBUG: CWD=${PWD}"

pushd "$(dirname "${IDENTITY_FILE}")"
"${REFLECT_BIN}" server --verbose --identity="$(basename "${IDENTITY_FILE}")" --serviceName="${SERVICE_NAME}"
