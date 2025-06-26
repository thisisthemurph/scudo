package scudo

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/scudo/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const accessTokenTTL = time.Minute
const accessTokenSecret = "test-secret"
const refreshTokenTTL = time.Hour

func init() {
	err := godotenv.Load(".env.test")
	if err != nil {
		panic(err)
	}
}

func testDatabase(t *testing.T) *sql.DB {
	t.Helper()

	connectionString := os.Getenv("DATABASE_URL")
	if connectionString == "" {
		t.Fatal("DATABASE_URL environment variable is not set")
	}

	db, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = db.Close()
	})

	return db
}

func resetDatabase(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.Exec(`DELETE FROM scudo.refresh_tokens`)
	require.NoError(t, err)

	_, err = db.Exec(`DELETE FROM scudo.users`)
	require.NoError(t, err)
}

func newTestScudo(t *testing.T, db *sql.DB) *Scudo {
	t.Helper()

	s, err := New(db, Options{
		AccessTokenTTL:    accessTokenTTL,
		AccessTokenSecret: accessTokenSecret,
		RefreshTokenTTL:   refreshTokenTTL,
	})
	require.NoError(t, err)

	resetDatabase(t, db)
	return s
}

func uniqueEmail() string {
	return fmt.Sprintf("user_%d@example.com", time.Now().UnixNano())
}

func TestSignUp_CreatesUser(t *testing.T) {
	start := time.Now()
	db := testDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	password := "securepassword123"

	response, err := sut.SignUp(context.Background(), email, password)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.User)

	assert.Equal(t, email, response.User.Email)
	assert.NotEmpty(t, response.User.ID)
	assert.True(t, response.User.CreatedAt.After(start))
	assert.Equal(t, response.User.CreatedAt, response.User.UpdatedAt)
}

func TestSignUp_ReturnsError_WhenEmailAlreadyExists(t *testing.T) {
	db := testDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	password := "securepassword123"

	_, err := sut.SignUp(context.Background(), email, password)
	require.NoError(t, err)

	_, err = sut.SignUp(context.Background(), email, password)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserAlreadyExists)
}

func TestSignIn_ReturnsError_WhenEmailNotFound(t *testing.T) {
	db := testDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	password := "securepassword123"

	_, err := sut.SignIn(context.Background(), email, password)
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestSignIn_ReturnsError_WhenPasswordIncorrect(t *testing.T) {
	db := testDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	password := "securepassword123"

	_, err := sut.SignUp(context.Background(), email, password)
	require.NoError(t, err)

	_, err = sut.SignIn(context.Background(), email, "incorrect-password")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestSignIn_ReturnsSignInResponse_WhenDetailsCorrect(t *testing.T) {
	db := testDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	password := "securepassword123"

	_, err := sut.SignUp(context.Background(), email, password)
	require.NoError(t, err)

	r, err := sut.SignIn(context.Background(), email, password)
	require.NoError(t, err)

	assert.NotNil(t, r)
	assert.NotNil(t, r.User)
	assert.NotEmpty(t, r.AccessToken)
	assert.NotEmpty(t, r.RefreshToken)
	assert.NotEmpty(t, r.User.ID)
	assert.Equal(t, email, r.User.Email)
}

func TestSignIn_PersistsRefreshToken_WhenDetailsCorrect(t *testing.T) {
	db := testDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	password := "securepassword123"

	_, err := sut.SignUp(context.Background(), email, password)
	require.NoError(t, err)

	r, err := sut.SignIn(context.Background(), email, password)
	require.NoError(t, err)

	assert.NotNil(t, r)
	assert.NotEmpty(t, r.RefreshToken)

	q := "select hashed_token, revoked from scudo.refresh_tokens where user_id = $1 limit 1;"

	var token repository.ScudoRefreshToken
	err = db.QueryRow(q, r.User.ID).Scan(&token.HashedToken, &token.Revoked)
	require.NoError(t, err)

	err = bcrypt.CompareHashAndPassword([]byte(token.HashedToken), []byte(r.RefreshToken))
	assert.NoError(t, err, "Expected the hashed refresh token to match")
	assert.False(t, token.Revoked)
}
