# Builds the AWS credential helper (aws_signing_helper) at a pinned commit, and the oracle that
# records the CreateSession requests it signs. `go install` verifies the helper's module against
# the Go checksum database.
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0

ARG HELPER_COMMIT=f17999e83885205544bda00553ffb907a16bf862
ENV GOTOOLCHAIN=local

RUN go install "github.com/aws/rolesanywhere-credential-helper@${HELPER_COMMIT}" \
    && mv /go/bin/rolesanywhere-credential-helper /usr/local/bin/aws_signing_helper

COPY oracle /src/oracle
RUN cd /src/oracle && go build -o /usr/local/bin/oracle .

ENTRYPOINT ["/usr/local/bin/oracle", "/usr/local/bin/aws_signing_helper"]
