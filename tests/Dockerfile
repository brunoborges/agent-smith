FROM golang:1.25-bookworm
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY examples ./examples
COPY tests/linux-smoke.sh /linux-smoke.sh
RUN CGO_ENABLED=0 go build -o /usr/local/sbin/agent-smith ./cmd/agent-smith
RUN useradd -m agent-smith-test
CMD ["sh", "-ec", "go vet ./... && AGENT_SMITH_ISOLATED_TEST=1 go test -count=1 -timeout=90s ./... && sh /linux-smoke.sh"]
