MIGRATION_DIR=migrations  
APP_CONFIG_FILE_NAME=amponin-server-config.yaml

run:
	go run ./ --config-file $(APP_CONFIG_FILE_NAME)

migrate_create:
	migrate create -ext sql -dir $(MIGRATION_DIR) -seq $(NAME)

migrate_up:
	migrate -path $(MIGRATION_DIR) -database $(DATABASE_URL) up

migrate_down:
	migrate -path $(MIGRATION_DIR) -database $(DATABASE_URL) down

migrate_force:
	migrate -path $(MIGRATION_DIR) -database $(DATABASE_URL) force $(VERSION) 

migrate_version:
	migrate -path $(MIGRATION_DIR) -database $(DATABASE_URL) version

