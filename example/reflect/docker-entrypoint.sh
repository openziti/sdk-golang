#!/usr/bin/env bash

set -x -e -u -o pipefail

REFLECT_DIR="${APP_HOME}/example/reflect"

if [[ -d "${REFLECT_DIR}" ]]; then
#    go build -mod=readonly -o "${REFLECT_DIR}" "${REFLECT_DIR}"
    go build -o "${REFLECT_DIR}" "${REFLECT_DIR}"
    REFLECT_BIN="${REFLECT_DIR}/reflect"
else
    REFLECT_BIN=$(which reflect) # installed in Dockerfile
fi

echo "DEBUG: CWD=${PWD}"
echo "DEBUG: ${REFLECT_DIR}"; ls -lA "${REFLECT_DIR}"

#pushd "${REFLECT_DIR}"
"${REFLECT_BIN}" server --verbose --identity="${REFLECT_DIR}/${ZITI_SDK_CONFIG}" --serviceName="${SERVICE_NAME}"
