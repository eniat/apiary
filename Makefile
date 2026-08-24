.PHONY: check clean iface
check:
	@./scripts/check-env.sh
clean:
	@docker rm -f $$(docker ps -aq --filter name=ap-) 2>/dev/null || true
iface:
	@echo br-$$(docker network inspect -f '{{.Id}}' apiary-net | cut -c1-12)
