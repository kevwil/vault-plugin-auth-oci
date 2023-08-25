#!/usr/bin/env bash

set -euo pipefail

#sleep 2
#env
#ls -aFl /.oci-credentials/
#cat /.oci-credentials/private.pem
/usr/bin/vault login -method=oci auth_type=resource role=vaultadminrole
