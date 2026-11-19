# Static musl builds of `apigw` (Dockerfile.build). One invocation per
# architecture, TARGET set to the musl triple:
#   TARGET=aarch64-unknown-linux-musl docker buildx bake ci
# The binary lands under ./target/<TARGET>/release/apigw (output type=local).

variable "TARGET" {
  default = "x86_64-unknown-linux-musl"
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

variable "GENERATE_SBOM" {
  default = "false"
}

group "default" {
  targets = ["ci"]
}

# The release build: reproducible, with a CycloneDX SBOM beside the binary.
#
# No `type=gha` cache. This target runs only from the release workflow, and an
# Actions cache written on a tag ref can only be read back by that same tag, so
# an entry a release uploaded would never be readable by the next one.
target "ci" {
  dockerfile = "Dockerfile.build"
  context    = "."
  output     = ["type=local,dest=."]
  args = {
    TARGET            = TARGET
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    GENERATE_SBOM     = GENERATE_SBOM
  }
}
