package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var COGNITO_JWKS_URL string

func generateSecretHash(username, clientID, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func ensureEnvValue(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("cannot load env: %s\n", key)
	}

	return value
}

func getUsernameAndPassowrd() (string, string) {
	if len(os.Args) != 3 {
		fmt.Println("please specify username and password")
		os.Exit(1)
	}

	return os.Args[1], os.Args[2]
}

func getToken(cfg aws.Config) *types.AuthenticationResultType {
	clientId := ensureEnvValue("CLIENT_ID")
	clientSecret := ensureEnvValue("CLIENT_SECRET")

	username, password := getUsernameAndPassowrd()

	secretHash := generateSecretHash(username, clientId, clientSecret)

	input := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(clientId),
		AuthParameters: map[string]string{
			"USERNAME":    username,
			"PASSWORD":    password,
			"SECRET_HASH": secretHash,
		},
	}

	svc := cognitoidentityprovider.NewFromConfig(cfg)
	result, err := svc.InitiateAuth(context.Background(), input)
	if err != nil {
		log.Fatalf("Auth request failed: %v\n", err)
	}

	return result.AuthenticationResult
}

func init() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("cannot load .env")
	}

	COGNITO_JWKS_URL = fmt.Sprintf("https://cognito-idp.ap-northeast-1.amazonaws.com/%s/.well-known/jwks.json", ensureEnvValue("POOL_ID"))
}

func verifyToken(signedToken string) jwt.Token {
	keySet, err := jwk.Fetch(context.Background(), COGNITO_JWKS_URL)
	if err != nil {
		log.Fatal(err)
	}

	verifiedToken, err := jwt.Parse([]byte(signedToken), jwt.WithKeySet(keySet))

	if err != nil {
		log.Fatal(err)
	}

	return verifiedToken
}

func revokeToken(cfg aws.Config, token *types.AuthenticationResultType) {
	svc := cognitoidentityprovider.NewFromConfig(cfg)

	clientId := ensureEnvValue("CLIENT_ID")
	clientSecret := ensureEnvValue("CLIENT_SECRET")

	revokeInput := cognitoidentityprovider.RevokeTokenInput{
		ClientId:     &clientId,
		ClientSecret: &clientSecret,
		Token:        token.RefreshToken,
	}

	ctx := context.Background()

	_, err := svc.RevokeToken(ctx, &revokeInput)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// get token using username and password
	result := getToken(cfg)

	// verify token using public keys
	token := verifyToken(*result.IdToken)

	// check expiration of token
	now := time.Now().UTC()
	exp := token.Expiration()
	if exp.After(now) {
		log.Fatal("id token is expiration")
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(token)

	// revoke refresh token
	revokeToken(cfg, result)
}
