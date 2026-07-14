.PHONY: build up down clean demo-attack demo-normal demo-all test lint install smol

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

clean: down
	docker compose down -v --rmi all
	rm -rf .tfdata/

demo-normal:
	docker compose exec demo-agents python /app/shopping_agent.py

demo-attack:
	docker compose exec attack-simulator python /app/attack_simulator.py

demo-all: up
	@echo "=== Running Normal Agent Demo ==="
	python scripts/run_demo.py --scenario normal
	@echo ""
	@echo "=== Running Attack Simulations ==="
	python scripts/run_demo.py --scenario attacks

install:
	pip install -e .

smol:
	zt-gateway --mode smol --port 8000

test-smol:
	python test_smol.py

test:
	docker compose exec ai-gateway pytest /app/tests/ -v

lint:
	docker compose exec ai-gateway flake8 /app/src/

logs:
	docker compose logs -f

terraform-init:
	cd terraform && terraform init

terraform-plan:
	cd terraform && terraform plan

terraform-apply:
	cd terraform && terraform apply

terraform-destroy:
	cd terraform && terraform destroy
