package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/DarlingGoose/credentials/oauth/oserver"
	"github.com/DarlingGoose/credentials/session"
	"github.com/DarlingGoose/credentials/user"
	"github.com/DarlingGoose/mserve"
	generators "github.com/DarlingGoose/mserve/generator"
	"github.com/DarlingGoose/rbac"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

/*
 */
func main() {
	ctx := context.Background()
	databaseConfig := mongoDatabaseConfigFromEnv()
	mongoDB, err := mongo.Connect(ctx, options.Client().ApplyURI(databaseConfig.URI))
	if err != nil {
		log.Fatal(err)
	}
	rbacManager, err := rbac.NewMongoStoreManager(ctx, mongoDB.Database(databaseConfig.RBACDatabase))
	if err != nil {
		log.Fatal(err)
	}
	secret, err := GenerateSecret(32)
	if err != nil {
		log.Fatal(err)
	}
	oServer := oserver.NewMongoServer(mongoDB.Database(databaseConfig.OAuthDatabase))
	//_,_ = oServer.RegisterClient(ctx, &oserver.OAuthClient{
	//	ClientID:           uuid.New().String(),
	//	ClientSecret:       uuid.New().String(),
	//	Name:               "Test",
	//	ImageURL:           "",
	//	RedirectURIs:       []string{"localhost:8080"},
	//	Scopes:             nil,
	//	TokenEndpointAuth:  "",
	//	GrantTypes:         nil,
	//	ResponseTypes:      nil,
	//	ConnectedUserCount: 0,
	//})
	ses := session.NewClient(oServer, rbacManager, secret, 24*time.Hour)
	s := mserve.NewServer("Example", rbacManager, []string{}, ses, mserve.SSLConfig{Port: 8080})

	userServer, err := user.NewServer(user.NewMongoDBStore(mongoDB, databaseConfig.UserDatabase, "user"), rbacManager, secret, "example.com", "Example", "https://dev.example.com:3000")
	if err != nil {
		log.Fatal(err)
	}
	s.SetupOServer(ctx, oServer).
		SetupRbac(ctx).
		SetupUserLogin(ctx, userServer).
		HealthCheck("/healthz", nil).
		GenerateOpenAPIDocs()

	_ = generators.NewGoClientGenerator(nil).Generate(generators.NewGenData(), s.Endpoints()...)

}

type mongoDatabaseConfig struct {
	URI           string
	RBACDatabase  string
	OAuthDatabase string
	UserDatabase  string
}

// mongoDatabaseConfigFromEnv keeps credentials, RBAC, and OAuth state inside
// databases chosen by this application. Set MSERVE_DATABASE to isolate a whole
// deployment, or use the per-store variables when those stores must be split.
//
// The default values preserve the example's original behaviour.
func mongoDatabaseConfigFromEnv() mongoDatabaseConfig {
	base := envOrDefault("MSERVE_DATABASE", "local")
	return mongoDatabaseConfig{
		URI:           envOrDefault("MSERVE_MONGO_URI", "mongodb://mongoadmin:secretpassword@localhost:27017/?authSource=admin"),
		RBACDatabase:  envOrDefault("MSERVE_RBAC_DATABASE", base),
		OAuthDatabase: envOrDefault("MSERVE_OAUTH_DATABASE", base),
		UserDatabase:  envOrDefault("MSERVE_USER_DATABASE", base),
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func GenerateSecret(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("secret length must be positive")
	}

	secret := make([]byte, length)
	// Read generates cryptographically secure random bytes and writes them into secret.
	// It returns the number of bytes read and an error, if any.
	n, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes for secret: %w", err)
	}
	if n != length {
		return nil, fmt.Errorf("expected to read %d bytes, but only read %d", length, n)
	}

	return secret, nil
}
