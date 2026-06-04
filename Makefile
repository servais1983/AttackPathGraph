.PHONY: install test demo docker-build

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

demo:
	attackpathgraph --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json --ascii

docker-build:
	docker build -t attackpathgraph .
