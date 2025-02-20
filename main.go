package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/VannestBun/chirpy/internal/auth"
	"github.com/VannestBun/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"hashed_password"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type userResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) printHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	responseText := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
`, cfg.fileserverHits.Load())
	w.Write([]byte(responseText))
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {
	platform := os.Getenv("PLATFORM")

	if platform != "dev" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	err := cfg.dbQueries.DeleteAllUser(context.Background())
	if err != nil {
		log.Println("Error deleting users:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	cleanedWords, err := validateAndCleanChirp(params.Body)
	if err != nil {
		respondWithError(w, 400, err.Error())
		return
	}

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		ID:     uuid.New(),
		Body:   cleanedWords,
		UserID: userID,
	})

	if err != nil {
		fmt.Printf("Database error: %v\n", err) // add this line
		respondWithError(w, 400, "Cannot Create Chirp")
		return
	}

	respBody := Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	dat, err := json.Marshal(respBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)
}

func validateAndCleanChirp(body string) (string, error) {
	// Check length
	if len(body) > 140 {
		return "", fmt.Errorf("chirp is too long")
	}

	// Clean the words
	cleanedBody := handleCleanedWords(body)

	return cleanedBody, nil
}

func handleCleanedWords(words string) string {
	wordsSlice := strings.Split(words, " ")
	for i, word := range wordsSlice {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			wordsSlice[i] = "****"
		}
	}
	return strings.Join(wordsSlice, " ")
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	response := map[string]string{
		"error": msg,
	}
	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func (cfg *apiConfig) handleUsers(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	hashedPass, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		HashedPassword: hashedPass,
		Email:          params.Email,
	})
	if err != nil {
		respondWithError(w, 400, "Cannot Create User")
		return
	}

	respBody := userResponse{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	dat, err := json.Marshal(respBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)

}

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {

	var dbChirps []database.Chirp
	var err error

	authorID := r.URL.Query().Get("author_id")
	if authorID != "" {
		userId, err := uuid.Parse(authorID)
		if err != nil {
			respondWithError(w, 404, "invalidId")
			return
		}
		dbChirps, err = cfg.dbQueries.GetChirpByUserID(context.Background(), userId)
		if err != nil {
			respondWithError(w, 400, "no chirps")
			return
		}
	} else {
		dbChirps, err = cfg.dbQueries.GetAllChirps(r.Context())
		if err != nil {
			respondWithError(w, 400, "no chirps")
			return
		}
	}

	// Transform database chirps into API chirps
	apiChirps := make([]Chirp, len(dbChirps))
	for i, dbChirp := range dbChirps {
		apiChirps[i] = Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		}
	}
	sortValue := r.URL.Query().Get("sort")
	if sortValue == "desc" {
		sort.Slice(apiChirps, func(i, j int) bool { return apiChirps[i].CreatedAt.After(apiChirps[j].CreatedAt) })
	} else {
		sort.Slice(apiChirps, func(i, j int) bool { return apiChirps[i].CreatedAt.Before(apiChirps[j].CreatedAt) })
	}

	jsonResponse, err := json.Marshal(apiChirps)
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(jsonResponse)

	// DB Query -> DB Struct -> API Struct -> JSON -> Client
}

func (cfg *apiConfig) GetOneChirp(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")

	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, 404, "invalidId")
		return
	}

	dbChirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, 404, "no chirps")
		return
	}

	// Transform database chirps into API chirps
	apiChirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}

	jsonResponse, err := json.Marshal(apiChirp)
	if err != nil {
		respondWithError(w, 500, "Internal Server Error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(jsonResponse)
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	// get by user by email
	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	expirationTime := 3600 // default 1 hour in seconds
	if params.ExpiresInSeconds != nil {
		if *params.ExpiresInSeconds > 3600 {
			expirationTime = 3600
		} else {
			expirationTime = *params.ExpiresInSeconds
		}
	}
	expiration := time.Second * time.Duration(expirationTime)

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expiration)
	if err != nil {
		respondWithError(w, 500, "Error creating token")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, 500, "Error creating Refresh Token")
		return
	}

	// Calculate the expiration time for the refresh token
	expiresAt := time.Now().Add(60 * 24 * time.Hour) // 60 days from now

	// Create the parameters for the refresh token
	refreshTokenEntry := database.CreateRefreshTokenParams{
		Token:     refreshToken, // The token value from MakeRefreshToken
		UserID:    user.ID,      // The user ID from the authenticated user
		ExpiresAt: expiresAt,    // Expiration date
	}

	// Insert the refresh token into the database
	_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), refreshTokenEntry)
	if err != nil {
		respondWithError(w, 500, "Error saving refresh token")
		return
	}

	// If the passwords match, return a 200 OK response and a copy of the user resource (without the password of course):
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // 200
	json.NewEncoder(w).Encode(userResponse{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,
	})
}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, 401, "missing or invalid Authorization header")
		return
	}
	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Query the database to validate the refresh token
	storedToken, err := cfg.dbQueries.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, 401, "error retrieving token or token not valid")
		return
	}

	// Set the token to expire in 1 hour
	expiration := time.Hour

	// Generate the access token using MakeJWT
	token, err := auth.MakeJWT(storedToken.UserID, cfg.jwtSecret, expiration)
	if err != nil {
		respondWithError(w, 500, "Error creating token")
		return
	}

	// Respond with the new token
	response := map[string]string{
		"token": token,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, 401, "missing or invalid Authorization header")
		return
	}
	refreshToken := strings.TrimPrefix(authHeader, "Bearer ")

	_, err := cfg.dbQueries.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, 401, "error retrieving token or token not valid")
		return
	}
	revokedAt := sql.NullTime{
		Time:  time.Now(), // The actual timestamp
		Valid: true,       // Indicates this is NOT NULL
	}
	updateRefresh := database.UpdateRefreshTokenParams{
		Token:     refreshToken,
		RevokedAt: revokedAt,
		UpdatedAt: time.Now(),
	}
	err = cfg.dbQueries.UpdateRefreshToken(r.Context(), updateRefresh)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error updating token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleUpdate(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, 401, "missing or invalid Authorization header")
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Invalid request body")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	updateParams := database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	}

	// Call the database method
	updatedUser, err := cfg.dbQueries.UpdateUser(r.Context(), updateParams)
	if err != nil {
		respondWithError(w, 500, "Failed to update user")
		return
	}

	response := userResponse{
		ID:        updatedUser.ID,
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
		Email:     updatedUser.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (cfg *apiConfig) handleDeleteChirp(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		respondWithError(w, 401, "missing or invalid Authorization header")
		return
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	// take chirp id from body request
	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, 404, "invalidId")
		return
	}
	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, 404, "no chirps")
		return
	}

	if chirp.UserID != userID {
		respondWithError(w, 403, "user not author of this chirp")
		return
	}

	err = cfg.dbQueries.DeleteChirp(context.Background(), chirpID)
	if err != nil {
		respondWithError(w, 500, "Internal server error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	type UserUpgradedData struct {
		UserID string `json:"user_id"`
	}

	type UserUpgradedEvent struct {
		Event string           `json:"event"`
		Data  UserUpgradedData `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	params := UserUpgradedEvent{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Invalid request body")
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	userId, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		respondWithError(w, 404, "invalidId")
		return
	}

	_, err = cfg.dbQueries.GetUserById(context.Background(), userId)
	if err != nil {
		respondWithError(w, 404, "User don't exist")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "ApiKey ") {
		respondWithError(w, 401, "missing or invalid Authorization header")
		return
	}

	apiKey := strings.TrimPrefix(authHeader, "ApiKey ")

	if apiKey != cfg.polkaKey {
		respondWithError(w, 401, "Not Auhthorized")
		return
	}

	err = cfg.dbQueries.UpgradeUser(context.Background())
	if err != nil {
		respondWithError(w, 400, "Invalid request body")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Printf("Error opening postgress database: %s", err)
	}

	dbQueries := database.New(db)

	const filepathRoot = "."
	const port = "8080"
	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		platform:  platform,
		jwtSecret: jwtSecret,
		polkaKey:  polkaKey,
	}

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))

	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /admin/metrics", apiCfg.printHits)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHits)

	mux.HandleFunc("POST /api/users", apiCfg.handleUsers)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET  /api/chirps", apiCfg.getAllChirps)
	mux.HandleFunc("GET  /api/chirps/{chirpID}", apiCfg.GetOneChirp)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)

	mux.HandleFunc("PUT /api/users", apiCfg.handleUpdate)

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handleDeleteChirp)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleUpgrade)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}
