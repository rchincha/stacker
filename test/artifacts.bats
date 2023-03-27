load helpers

function setup() {
    stacker_setup
}

function teardown() {
    cleanup
}

@test "stacker.yaml with sbom imports can run" {
    cat > stacker.yaml <<EOF
centos:
    from:
        type: oci
        url: $CENTOS_OCI
    bom: true
    run: |
        touch /foo
        echo "test" > /stacker-artifacts/test.sbom
EOF
    stacker build
    ls -alR .stacker/artifacts/centos
    [ -f .stacker/artifacts/centos/test.sbom ]
    [ -f .stacker/artifacts/centos/libs.spdx ]
    [ -f .stacker/artifacts/centos/inventory.json ]
    cat .stacker/artifacts/centos/inventory.json | jq .
}
