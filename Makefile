.PHONY: check clean
check:
	@./scripts/check-env.sh
clean:
	@docker rm -f $$(docker ps -aq --filter name=ap-) 2>/dev/null || true
