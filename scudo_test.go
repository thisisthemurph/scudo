package scudo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/scudo/internal/repository"
	"golang.org/x/crypto/bcrypt"

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

func TestSignOut_ReturnsError_WhenUserNotSignedIn(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	err = sut.Auth.SignOut(context.Background(), rr, req)
	require.Error(t, err)
}

func TestSignOut_UnsetsTheCookies(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	rr = httptest.NewRecorder()
	err = sut.Auth.SignOut(context.Background(), rr, req)
	require.NoError(t, err)

	accessTokenCookie := getCookie(t, rr, AccessTokenCookieKey)
	assert.Equal(t, "", accessTokenCookie.Value)
	assert.Equal(t, -1, accessTokenCookie.MaxAge)
	assert.True(t, accessTokenCookie.Expires.Before(time.Now()), "cookie should be expired")
}

func TestSignOut_RevokesTheRefreshToken(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	signupResponse, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	err = sut.Auth.SignOut(context.Background(), httptest.NewRecorder(), req)
	require.NoError(t, err)

	var revoked bool
	query := "select revoked from scudo.refresh_tokens where user_id = $1;"
	err = db.QueryRow(query, signupResponse.User.ID).Scan(&revoked)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func getCookie(t *testing.T, rr *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	cookies := rr.Result().Cookies()
	for i := len(cookies) - 1; i >= 0; i-- {
		if cookies[i].Name == name {
			return cookies[i]
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

func TestRefreshToken_ReturnsError_WhenRefreshTokenNotFound(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Create request without refresh token cookie
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	// Only add access token cookie, not refresh token
	for _, c := range rr.Result().Cookies() {
		if c.Name == AccessTokenCookieKey {
			req.AddCookie(c)
		}
	}

	rr = httptest.NewRecorder()
	_, err = sut.Auth.RefreshToken(context.Background(), rr, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token not found")
}

func TestRefreshToken_ReturnsError_WhenAccessTokenMissing(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Create request without access token cookie
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	// Only add refresh token cookie, not access token
	for _, c := range rr.Result().Cookies() {
		if c.Name == RefreshTokenCookieKey {
			req.AddCookie(c)
		}
	}

	rr = httptest.NewRecorder()
	_, err = sut.Auth.RefreshToken(context.Background(), rr, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to determine user from access token")
}

func TestRefreshToken_ReturnsError_WhenRefreshTokenInvalid(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Create request with invalid refresh token
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		if c.Name == AccessTokenCookieKey {
			req.AddCookie(c)
		}
	}
	// Add invalid refresh token
	req.AddCookie(&http.Cookie{
		Name:  RefreshTokenCookieKey,
		Value: "invalid_refresh_token",
	})

	rr = httptest.NewRecorder()
	_, err = sut.Auth.RefreshToken(context.Background(), rr, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

func TestRefreshToken_ReturnsError_WhenRefreshTokenRevoked(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	signupResponse, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Revoke the refresh token
	_, err = db.Exec("UPDATE scudo.refresh_tokens SET revoked = true WHERE user_id = $1", signupResponse.User.ID)
	require.NoError(t, err)

	// Try to refresh with revoked token
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	rr = httptest.NewRecorder()
	_, err = sut.Auth.RefreshToken(context.Background(), rr, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

func TestRefreshToken_ReturnsSignInResponse_WhenTokensValid(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	signinResponse, err := sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Create refresh request
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	// Wait a bit to ensure new token has different timestamp
	time.Sleep(100 * time.Millisecond)

	rr = httptest.NewRecorder()
	refreshResponse, err := sut.Auth.RefreshToken(context.Background(), rr, req)
	require.NoError(t, err)
	require.NotNil(t, refreshResponse)

	// Verify response structure
	assert.Equal(t, signinResponse.User.ID, refreshResponse.User.ID)
	assert.Equal(t, signinResponse.User.Email, refreshResponse.User.Email)
	assert.NotEmpty(t, refreshResponse.AccessToken)
	assert.NotEmpty(t, refreshResponse.RefreshToken)

	// Verify new tokens are different from old ones
	assert.NotEqual(t, signinResponse.AccessToken, refreshResponse.AccessToken)
	assert.NotEqual(t, signinResponse.RefreshToken, refreshResponse.RefreshToken)
}

func TestRefreshToken_SetsCookies_WhenTokensValid(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Create refresh request
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	rr = httptest.NewRecorder()
	refreshResponse, err := sut.Auth.RefreshToken(context.Background(), rr, req)
	require.NoError(t, err)

	// Verify cookies are set
	accessTokenCookie := getCookie(t, rr, AccessTokenCookieKey)
	assert.NotNil(t, accessTokenCookie)
	assert.Equal(t, refreshResponse.AccessToken, accessTokenCookie.Value)
	assert.True(t, accessTokenCookie.HttpOnly)

	refreshTokenCookie := getCookie(t, rr, RefreshTokenCookieKey)
	assert.NotNil(t, refreshTokenCookie)
	assert.Equal(t, refreshResponse.RefreshToken, refreshTokenCookie.Value)
	assert.True(t, refreshTokenCookie.HttpOnly)
}

func TestRefreshToken_RotatesRefreshToken_WhenTokensValid(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	signupResponse, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	signinResponse, err := sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Get initial refresh token count
	var initialCount int
	err = db.QueryRow("SELECT COUNT(*) FROM scudo.refresh_tokens WHERE user_id = $1", signupResponse.User.ID).Scan(&initialCount)
	require.NoError(t, err)

	// Create refresh request
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	rr = httptest.NewRecorder()
	refreshResponse, err := sut.Auth.RefreshToken(context.Background(), rr, req)
	require.NoError(t, err)

	// Verify new refresh token was created
	var newCount int
	err = db.QueryRow("SELECT COUNT(*) FROM scudo.refresh_tokens WHERE user_id = $1", signupResponse.User.ID).Scan(&newCount)
	require.NoError(t, err)
	assert.Equal(t, initialCount+1, newCount)

	// Verify old refresh token is revoked
	var revokedCount int
	err = db.QueryRow("SELECT COUNT(*) FROM scudo.refresh_tokens WHERE user_id = $1 AND revoked = true", signupResponse.User.ID).Scan(&revokedCount)
	require.NoError(t, err)
	assert.Equal(t, 1, revokedCount)

	// Verify new refresh token is valid
	var validCount int
	err = db.QueryRow("SELECT COUNT(*) FROM scudo.refresh_tokens WHERE user_id = $1 AND revoked = false", signupResponse.User.ID).Scan(&validCount)
	require.NoError(t, err)
	assert.Equal(t, 1, validCount)

	// Verify old refresh token can't be used again
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  AccessTokenCookieKey,
		Value: refreshResponse.AccessToken,
	})
	req.AddCookie(&http.Cookie{
		Name:  RefreshTokenCookieKey,
		Value: signinResponse.RefreshToken, // Use old refresh token
	})

	rr = httptest.NewRecorder()
	_, err = sut.Auth.RefreshToken(context.Background(), rr, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

func TestRefreshToken_WorksWithExpiredAccessToken(t *testing.T) {
	db := createTestDatabase(t)
	// Create scudo with very short access token TTL
	sut, err := New(db, &Options{
		AccessTokenTTL:    100 * time.Millisecond, // Very short TTL
		AccessTokenSecret: accessTokenSecret,
		RefreshTokenTTL:   refreshTokenTTL,
	})
	require.NoError(t, err)
	resetDatabase(t, db)

	email := uniqueEmail()
	_, err = sut.Auth.SignUp(context.Background(), email, defaultPassword, nil)
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Wait for access token to expire
	time.Sleep(200 * time.Millisecond)

	// Create refresh request with expired access token
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	rr = httptest.NewRecorder()
	refreshResponse, err := sut.Auth.RefreshToken(context.Background(), rr, req)
	require.NoError(t, err)
	require.NotNil(t, refreshResponse)

	// Verify we got a new valid access token
	assert.NotEmpty(t, refreshResponse.AccessToken)
	assert.NotEmpty(t, refreshResponse.RefreshToken)

	// Verify new access token is valid
	token, err := jwt.Parse(refreshResponse.AccessToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(accessTokenSecret), nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

func TestRefreshToken_GeneratesValidJWT_WhenTokensValid(t *testing.T) {
	db := createTestDatabase(t)
	sut := newTestScudo(t, db)

	email := uniqueEmail()
	_, err := sut.Auth.SignUp(context.Background(), email, defaultPassword, &SignUpOptions{
		Data: map[string]any{
			"name": "Test User",
			"role": "user",
		},
	})
	require.NoError(t, err)

	// Sign in to get tokens
	rr := httptest.NewRecorder()
	_, err = sut.Auth.SignIn(context.Background(), rr, email, defaultPassword)
	require.NoError(t, err)

	// Create refresh request
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	rr = httptest.NewRecorder()
	refreshResponse, err := sut.Auth.RefreshToken(context.Background(), rr, req)
	require.NoError(t, err)

	// Parse and verify the new JWT
	token, err := jwt.ParseWithClaims(refreshResponse.AccessToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(accessTokenSecret), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	claims := token.Claims.(jwt.MapClaims)
	assert.Equal(t, email, claims["email"])
	assert.Equal(t, refreshResponse.User.ID.String(), claims["sub"])
	assert.NotEmpty(t, claims["iat"])
	assert.NotEmpty(t, claims["exp"])

	// Verify metadata is included
	metadata := claims["metadata"].(map[string]interface{})
	assert.Equal(t, "Test User", metadata["name"])
	assert.Equal(t, "user", metadata["role"])
}
