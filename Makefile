.PHONY: check clean iface bpf attach detach test test-redirect
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
