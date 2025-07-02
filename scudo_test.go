package scudo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/scudo/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const (
	accessTokenTTL    = time.Minute
	accessTokenSecret = "test-secret"
	refreshTokenTTL   = time.Hour
	defaultPassword   = "secure_password_123"
)

func init() {
	_ = godotenv.Load(".env.test")
}

func createTestDatabase(t *testing.T) *sql.DB {
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

	s, err := New(db, &Options{
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
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	response, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NotNil(t, response.User)

	assert.Equal(t, email, response.User.Email)
	assert.NotEmpty(t, response.User.ID)
	assert.True(t, response.User.CreatedAt.After(start))
	assert.Equal(t, response.User.CreatedAt, response.User.UpdatedAt)

	// If no metadata has been passed into the signup method, the resulting user metadata should be an empty map.
	assert.IsType(t, make(map[string]any), response.User.MetadataMap)
	assert.Empty(t, response.User.MetadataMap)
	assert.Equal(t, "{}", string(response.User.Metadata))
}

type userMetadata struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type nestedUserMetadata struct {
	Inner userMetadata `json:"inner"`
	Port  string       `json:"p"`
}

func TestSignUp_PersistsUserMetadata(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	testCases := []struct {
		name       string
		data       any
		expected   map[string]any
		testStruct func(t *testing.T, data json.RawMessage)
	}{
		{
			name: "with generic map",
			data: map[string]any{
				"name": "Bob",
				"age":  36,
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  float64(36), // Go doesn't know what this should be, so uses float64
			},
		},
		{
			name: "with strict map",
			data: map[string]string{
				"name": "Bob",
				"age":  "36",
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  "36",
			},
		},
		{
			name: "with nested map",
			data: map[string]any{
				"id": 1,
				"user": map[string]any{
					"name": "Bob",
					"age":  36,
				},
				"scores": []int{1, 2, 3},
			},
			expected: map[string]any{
				"id": float64(1),
				"user": map[string]any{
					"name": "Bob",
					"age":  float64(36),
				},
				"scores": []interface{}{float64(1), float64(2), float64(3)},
			},
		},
		{
			name: "with struct data",
			data: userMetadata{
				Name: "Bob",
				Age:  36,
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  float64(36),
			},
			testStruct: func(t *testing.T, data json.RawMessage) {
				var x userMetadata
				err := json.Unmarshal(data, &x)
				require.NoError(t, err)
				assert.Equal(t, "Bob", x.Name)
				assert.Equal(t, 36, x.Age)
			},
		},
		{
			name: "with struct data",
			data: userMetadata{
				Name: "Bob",
				Age:  36,
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  float64(36),
			},
			testStruct: func(t *testing.T, data json.RawMessage) {
				var x userMetadata
				err := json.Unmarshal(data, &x)
				require.NoError(t, err)
				assert.Equal(t, "Bob", x.Name)
				assert.Equal(t, 36, x.Age)
			},
		},
		{
			name: "with nested struct data",
			data: nestedUserMetadata{
				Inner: userMetadata{
					Name: "Bob",
					Age:  36,
				},
				Port: "3000",
			},
			expected: map[string]any{
				"inner": map[string]any{
					"name": "Bob",
					"age":  float64(36),
				},
				"p": "3000",
			},
			testStruct: func(t *testing.T, data json.RawMessage) {
				var x nestedUserMetadata
				err := json.Unmarshal(data, &x)
				require.NoError(t, err)
				assert.Equal(t, "Bob", x.Inner.Name)
				assert.Equal(t, 36, x.Inner.Age)
				assert.Equal(t, "3000", x.Port)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueEmail()
			options := &SignUpOptions{
				Data: tc.data,
			}
			response, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, options)
			require.NoError(t, err)
			require.NotNil(t, response)
			require.NotNil(t, response.User)

			assert.IsType(t, make(map[string]any), response.User.MetadataMap)
			assert.Equal(t, tc.expected, response.User.MetadataMap)
			if tc.testStruct != nil {
				tc.testStruct(t, response.User.Metadata)
			}
		})
	}
}

func TestSignUp_ReturnsError_WhenEmailAlreadyExists(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	_, err = sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserAlreadyExists)
}

func TestSignIn_ReturnsError_WhenEmailNotFound(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignIn(context.Background(), httptest.NewRecorder(), email, defaultPassword)
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestSignIn_ReturnsError_WhenPasswordIncorrect(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	_, err = sut.Auth.SignIn(context.Background(), httptest.NewRecorder(), email, "incorrect-password")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestSignIn_ReturnsSignInResponse_WhenDetailsCorrect(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	r, err := sut.Auth.SignIn(context.Background(), httptest.NewRecorder(), email, defaultPassword)
	require.NoError(t, err)

	assert.NotNil(t, r)
	assert.NotNil(t, r.User)
	assert.NotEmpty(t, r.AccessToken)
	assert.NotEmpty(t, r.RefreshToken)
	assert.NotEmpty(t, r.User.ID)
	assert.Equal(t, email, r.User.Email)
}

func TestSignIn_IncludesMetadataOnJWTAccessToken_WhenSignedUpWithMetadata(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	testCases := []struct {
		name     string
		data     any
		expected map[string]any
	}{
		{
			name: "with generic map",
			data: map[string]any{
				"name": "Bob",
				"age":  36,
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  float64(36), // Go doesn't know what this should be, so uses float64
			},
		},
		{
			name: "with strict map",
			data: map[string]string{
				"name": "Bob",
				"age":  "36",
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  "36",
			},
		},
		{
			name: "with nested map",
			data: map[string]any{
				"id": 1,
				"user": map[string]any{
					"name": "Bob",
					"age":  36,
				},
				"scores": []int{1, 2, 3},
			},
			expected: map[string]any{
				"id": float64(1),
				"user": map[string]any{
					"name": "Bob",
					"age":  float64(36),
				},
				"scores": []interface{}{float64(1), float64(2), float64(3)},
			},
		},
		{
			name: "with struct data",
			data: userMetadata{
				Name: "Bob",
				Age:  36,
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  float64(36),
			},
		},
		{
			name: "with struct data",
			data: userMetadata{
				Name: "Bob",
				Age:  36,
			},
			expected: map[string]any{
				"name": "Bob",
				"age":  float64(36),
			},
		},
		{
			name: "with nested struct data",
			data: nestedUserMetadata{
				Inner: userMetadata{
					Name: "Bob",
					Age:  36,
				},
				Port: "3000",
			},
			expected: map[string]any{
				"inner": map[string]any{
					"name": "Bob",
					"age":  float64(36),
				},
				"p": "3000",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueEmail()
			_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, &SignUpOptions{
				Data: tc.data,
			})
			require.NoError(t, err)
			r, err := sut.Auth.SignIn(context.Background(), httptest.NewRecorder(), email, defaultPassword)
			require.NoError(t, err)
			require.NotNil(t, r)
			require.NotEmpty(t, r.AccessToken)

			at, err := jwt.ParseWithClaims(r.AccessToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(accessTokenSecret), nil
			})
			require.NoError(t, err)
			require.NotNil(t, at)
			assert.NoError(t, at.Claims.Valid())

			claims := at.Claims.(jwt.MapClaims)
			assert.NotEmpty(t, claims["sub"])
			assert.Equal(t, email, claims["email"])
			assert.NotEmpty(t, claims["iat"])
			assert.NotEmpty(t, claims["exp"])
			assert.Equal(t, tc.expected, claims["metadata"])
		})
	}
}

func TestSignIn_HasCorrectJWTAccessToken_WhenDetailsCorrect(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	r, err := sut.Auth.SignIn(context.Background(), httptest.NewRecorder(), email, defaultPassword)
	require.NoError(t, err)

	assert.NotNil(t, r)
	assert.NotEmpty(t, r.AccessToken)
	token, err := jwt.Parse(r.AccessToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(accessTokenSecret), nil
	})
	require.NoError(t, err)
	require.NotNil(t, token)
	require.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	u := getUserByEmail(t, db, email)
	assert.Equal(t, email, claims["email"])
	assert.Equal(t, u.ID.String(), claims["sub"])
}

func TestSignIn_SetsCookies_WhenDetailsCorrect(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	r, err := sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	accessTokenCookie := getCookie(t, rr, AccessTokenCookieKey)
	assert.NotNil(t, accessTokenCookie)
	assert.Equal(t, r.AccessToken, accessTokenCookie.Value)

	refreshTokenCookie := getCookie(t, rr, RefreshTokenCookieKey)
	assert.NotNil(t, refreshTokenCookie)
	assert.Equal(t, r.RefreshToken, refreshTokenCookie.Value)
}

func TestSignIn_PersistsRefreshToken_WhenDetailsCorrect(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	r, err := sut.Auth.SignIn(context.Background(), httptest.NewRecorder(), email, defaultPassword)
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

func getCookie(t *testing.T, rr *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func getUserByEmail(t *testing.T, db *sql.DB, email string) repository.ScudoUser {
	t.Helper()

	r := repository.New(db)
	u, err := r.GetUserByEmail(context.Background(), email)
	require.NoError(t, err)
	return u
}
