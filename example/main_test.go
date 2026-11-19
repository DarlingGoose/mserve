package main

import "testing"

func TestMongoDatabaseConfigFromEnv(t *testing.T) {
	t.Setenv("MSERVE_MONGO_URI", "mongodb://db.example:27017")
	t.Setenv("MSERVE_DATABASE", "learning_api")
	t.Setenv("MSERVE_RBAC_DATABASE", "learning_rbac")

	config := mongoDatabaseConfigFromEnv()
	if config.URI != "mongodb://db.example:27017" {
		t.Fatalf("URI = %q", config.URI)
	}
	if config.RBACDatabase != "learning_rbac" {
		t.Fatalf("RBACDatabase = %q", config.RBACDatabase)
	}
	if config.OAuthDatabase != "learning_api" || config.UserDatabase != "learning_api" {
		t.Fatalf("base database was not applied: %#v", config)
	}
}

func TestMongoDatabaseConfigDefaults(t *testing.T) {
	for _, name := range []string{
		"MSERVE_MONGO_URI",
		"MSERVE_DATABASE",
		"MSERVE_RBAC_DATABASE",
		"MSERVE_OAUTH_DATABASE",
		"MSERVE_USER_DATABASE",
	} {
		t.Setenv(name, "")
	}

	config := mongoDatabaseConfigFromEnv()
	if config.URI != "mongodb://mongoadmin:secretpassword@localhost:27017/?authSource=admin" {
		t.Fatalf("URI = %q", config.URI)
	}
	if config.RBACDatabase != "local" || config.OAuthDatabase != "local" || config.UserDatabase != "local" {
		t.Fatalf("database defaults = %#v", config)
	}
}
