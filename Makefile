IMAGE    := ucode-fw4-test:latest

.PHONY: image test shell package

image:
	docker build -t $(IMAGE) .

test: image
	docker run --rm \
		--ulimit nofile=4096:4096 \
		-v $(CURDIR):/app \
		-w /app \
		$(IMAGE) \
		utest tests/unit/ tests/integration/

shell: image
	docker run --rm -it \
		-v $(CURDIR):/app \
		-w /app \
		$(IMAGE) \
		sh
