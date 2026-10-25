.PHONY: check clean iface bpf attach detach test test-redirect test-detect test-affinity
check:
	@./scripts/check-env.sh
clean:
	@docker rm -f $$(docker ps -aq --filter name=ap-) 2>/dev/null || true
iface:
	@echo br-$$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)
bpf:
	@clang -O2 -g -Wall -target bpf -c dataplane/redirect.bpf.c -o dataplane/redirect.bpf.o
attach: bpf
	@sudo ./scripts/attach.sh
detach:
	@sudo ./scripts/detach.sh
test:
	@cd orchestrator && go test ./...
	@cd dataplane && go test ./...
test-redirect:
	@cd dataplane && go build -o /tmp/apiary-loader .
	@sudo ./scripts/test-redirect.sh
test-detect:
	@cd dataplane && go build -o /tmp/apiary-loader .
	@sudo ./scripts/test-detect.sh
test-affinity:
	@cd dataplane && go build -o /tmp/apiary-loader .
	@cd orchestrator && go build -o /tmp/apiary-reap ./cmd/reap
	@cd orchestrator && go build -o /tmp/apiary-pool ./cmd/pool
	@sudo ./scripts/test-affinity.sh
