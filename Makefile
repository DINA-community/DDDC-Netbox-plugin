.PHONY: tests lint smoke-test

lint:
	# Requires optional 'dev' dependencies
	# Checks for Python syntax errors and undefined names
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	# exit-zero treats all errors as warnings
	flake8 . --count --exit-zero --max-complexity=10 --statistics
	git ls-files '*.py' | xargs pylint

tests:
	docker compose up -d --build --wait --wait-timeout 600
	# Include dcim.tests.test_views.DeviceTypeTestCase because d3c overrides DeviceType add/edit views
	docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py test d3c dcim.tests.test_views.DeviceTypeTestCase || (docker compose logs --no-color netbox; docker compose down --volumes; exit 1)
	docker compose down --volumes

smoke-test:
	docker compose up -d --build --wait --wait-timeout 600
	docker compose ps -a
	docker-ci/smoke-test.sh http://localhost:8000 || (docker compose logs --no-color netbox; docker compose down --volumes; exit 1)
	docker compose down --volumes
