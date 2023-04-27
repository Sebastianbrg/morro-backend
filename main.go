package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type GlobalData struct {
	User         User
	Ride         Ride
	UserSession  UserSession
	LinkedInInfo LinkedInUserInfo
	CompanyStats CompanyStats
	UserStats    UserStats
	DistanceReq  DistanceRequest
	Leaderboard  []CompanyStats // Add this field
}
type Company struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	LogoURL string `json:"logo_url"`
}

type User struct {
	ID         int
	FirstName  string
	LastName   string
	CompanyID  int
	LinkedinID string
}

type Ride struct {
	ID        int
	UserID    int
	Distance  float64
	CO2Saved  float64
	Timestamp time.Time
}
type UserSession struct {
	CompanyID              int
	UserID                 int // Database user ID
	FirstName              string
	LastName               string
	Email                  string
	LinkedInID             string
	AppleID                string
	LinkedInAccessToken    string
	LinkedInRefreshToken   string
	LinkedInExpiresIn      int64
	LinkedInTokenCreatedAt int64
	AppleAccessToken       string
	AppleRefreshToken      string
	AppleExpiresIn         int64
	AppleTokenCreatedAt    int64
}

type LinkedInUserInfo struct {
	ID        string `json:"id"`
	FirstName struct {
		Localized struct {
			EnUS string `json:"en_US"`
		} `json:"localized"`
	} `json:"firstName"`
	LastName struct {
		Localized struct {
			EnUS string `json:"en_US"`
		} `json:"localized"`
	} `json:"lastName"`
	Email struct {
		EmailAddress string `json:"emailAddress"`
	} `json:"elements"`
}

type CompanyStats struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	TotalDistance float64 `json:"total_distance"`
	TotalCO2Saved float64 `json:"total_co2_saved"`
	LogoURL       string  `json:"logo_url"`
}

type UserStats struct {
	TotalDistance float64 `json:"total_distance"`
	TotalCO2Saved float64 `json:"total_co2_saved"`
}

type DistanceRequest struct {
	Distance float64 `json:"distance"`
	CO2Saved float64
}

type UpdateCompanyRequest struct {
	UserID    int `json:"user_id"`
	CompanyID int `json:"company_id"`
}

var (
	clientID     string
	clientSecret string
	redirectURI  string
)

type contextKey string

const userIDKey contextKey = "userID"

var db *sql.DB
var rdb *redis.Client
var ctx = context.Background()
var userDataCache sync.Map

// Sign the token using a secret key
var jwtSecretKey = []byte(os.Getenv("JWT_SECRET"))

func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	clientID = os.Getenv("LINKEDIN_CLIENT_ID")
	clientSecret = os.Getenv("LINKEDIN_CLIENT_SECRET")
	redirectURI = os.Getenv("LINKEDIN_REDIRECT_URI")

	db, err = openConnection()
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}
	defer db.Close()

	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST"),
		Password: os.Getenv("REDIS_SECRET"), // no password set
		DB:       0,                         // use default DB
	})

	// Other code, e.g., setting up HTTP routes

	err = createTables(db)
	if err != nil {
		log.Fatalf("Error creating companies table: %v", err)
	}

	/* err = generateSyntheticData(db) // Generate 5 companies, 50 users, and 200 rides
	if err != nil {
		log.Fatalf("Error generating synthetic data: %v", err)
	} */

	http.Handle("/user", jwtAuthMiddleware(http.HandlerFunc(getUserDataHandler)))
	http.Handle("/ride/complete", jwtAuthMiddleware(http.HandlerFunc(rideHandler)))
	http.HandleFunc("/auth/linkedin", linkedinAuthHandler)
	http.HandleFunc("/auth/linkedin/callback", linkedinCallbackHandler)
	http.HandleFunc("/company/leaderboard/", handleGetLeaderboard)
	http.Handle("/company/update", jwtAuthMiddleware(http.HandlerFunc(updateCompanyHandler)))
	http.Handle("/companies", jwtAuthMiddleware(http.HandlerFunc(getAllCompaniesHandler())))

	// Add the new route for the getUserInfoHandler

	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))

}

func updateCompanyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fmt.Println("Invalid method")
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var req UpdateCompanyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Get the user ID from the context
	contextUserID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		http.Error(w, "Error getting user ID from context", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET company_id = $1 WHERE id = $2", req.CompanyID, contextUserID)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error updating company", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Company updated successfully")
}

// GetCompanyByID retrieves a company by its ID from the database
func getCompanyByID(db *sql.DB, id int) (Company, error) {
	var company Company
	query := `SELECT id, name, logo_url FROM companies WHERE id = $1`
	err := db.QueryRow(query, id).Scan(&company.ID, &company.Name, &company.LogoURL)
	return company, err
}

// GetUserByID retrieves a user by its ID from the database
func getUserByID(db *sql.DB, id int) (User, error) {
	var user User
	query := `SELECT id, first_name, last_name, company_id, linkedin_id FROM users WHERE id = $1`
	err := db.QueryRow(query, id).Scan(&user.ID, &user.FirstName, &user.LastName, &user.CompanyID, &user.LinkedinID)
	return user, err
}

// GetRidesByUserID retrieves all rides of a user by the user's ID from the database
func getRidesByUserID(db *sql.DB, userID int) ([]Ride, error) {
	var rides []Ride
	query := `SELECT id, user_id, distance, co2_saved, timestamp FROM rides WHERE user_id = $1`
	rows, err := db.Query(query, userID)
	if err != nil {
		return rides, err
	}
	defer rows.Close()

	for rows.Next() {
		var ride Ride
		err = rows.Scan(&ride.ID, &ride.UserID, &ride.Distance, &ride.CO2Saved, &ride.Timestamp)
		if err != nil {
			return rides, err
		}
		rides = append(rides, ride)
	}

	return rides, nil
}

func getUserDataHandler(w http.ResponseWriter, r *http.Request) {
	var globalData GlobalData

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the user ID from the context
	contextUserID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		http.Error(w, "Error getting user ID from context", http.StatusInternalServerError)
		return
	}

	/*
		redisKey := fmt.Sprintf("user:%d", int(contextUserID))
		userData, err := rdb.Get(ctx, redisKey).Result()
	*/

	// Fetch the leaderboard data
	leaderboard, err := getLeaderboard()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch user, company, and ride data based on the user ID
	user, err := getUserByID(db, contextUserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	company, err := getCompanyByID(db, user.CompanyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rides, err := getRidesByUserID(db, contextUserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Populate the GlobalData structure with the fetched data
	globalData = GlobalData{
		User:        user,
		UserSession: UserSession{CompanyID: user.CompanyID, UserID: user.ID},
		CompanyStats: CompanyStats{
			ID:      company.ID,
			Name:    company.Name,
			LogoURL: company.LogoURL, // Add this field
		},
		Leaderboard: leaderboard, // Leaderboard data
	}

	for _, ride := range rides {
		globalData.UserStats.TotalDistance += ride.Distance
		globalData.UserStats.TotalCO2Saved += ride.CO2Saved
	}

	// Store the user data in Redis
	userDataJSON, err := json.Marshal(globalData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = rdb.Set(ctx, fmt.Sprintf("user_data:%d", contextUserID), userDataJSON, 0).Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the GlobalData structure as a JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalData)

}

func jwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the JWT token from the request header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Split the header into "Bearer" and the actual token.
		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		// Get the token without the "Bearer" prefix.
		tokenString := headerParts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["userID"] == nil {
			fmt.Println("Invalid token claims")
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userID, ok := claims["userID"].(float64)
		fmt.Println(userID, " ------------------- user ---------------")
		if !ok {
			fmt.Println("Invalid token claims userID")
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Check token expiration
		_, ok = claims["exp"].(float64)
		if !ok {
			fmt.Println("Invalid expiry of token. Request a new one")

			http.Error(w, "Invalid expiry of token. Request a new one: ", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, int(userID))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getUserByLinkedinID(linkedinID string) (*User, error) {
	var user User
	query := `SELECT id, first_name, last_name, company_id, linkedin_id FROM users WHERE linkedin_id = $1`
	err := db.QueryRow(query, linkedinID).Scan(&user.ID, &user.FirstName, &user.LastName, &user.CompanyID, &user.LinkedinID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func handleGetLeaderboard(w http.ResponseWriter, r *http.Request) {
	leaderboard, err := getLeaderboard()
	if err != nil {
		fmt.Println("6")
		http.Error(w, "Error retrieving leaderboard", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(leaderboard)
}

func getLeaderboard() ([]CompanyStats, error) {
	query := `SELECT c.id, c.name, SUM(r.distance) as total_distance, SUM(r.co2_saved) as total_co2_saved
              FROM companies c
              JOIN users u ON u.company_id = c.id
              JOIN rides r ON u.id = r.user_id
              GROUP BY c.id
              ORDER BY total_co2_saved DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leaderboard []CompanyStats

	for rows.Next() {
		var entry CompanyStats

		err := rows.Scan(&entry.ID, &entry.Name, &entry.TotalDistance, &entry.TotalCO2Saved)
		if err != nil {
			return nil, err
		}

		leaderboard = append(leaderboard, entry)
	}

	return leaderboard, rows.Err()
}

func randFloat(reader io.Reader) (float64, error) {
	max := 1 << 53
	bigInt, err := rand.Int(reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return float64(bigInt.Int64()) / float64(max), nil
}

func rideHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DistanceRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the user ID from the context
	contextUserID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		http.Error(w, "Error getting user ID from context", http.StatusInternalServerError)
		return
	}

	if req.Distance == 0 {
		fmt.Println("people are not really using the service. Userid: ", contextUserID)
		http.Error(w, "Distance needs to further than 0 meter", http.StatusNotModified)
		return
	}

	// Calculate CO2 saved
	carEmissionFactor := 0.12 // kg CO2 per km (average car emission factor)
	co2Saved := req.Distance * carEmissionFactor

	// Create a new Ride instance
	ride := Ride{
		Distance:  req.Distance,
		CO2Saved:  co2Saved, //
		UserID:    contextUserID,
		Timestamp: time.Now(),
	}

	// Insert the ride into the database
	err = insertRide(db, &ride)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)

}

func insertRide(db *sql.DB, ride *Ride) error {
	query := `INSERT INTO rides (distance, co2_saved, user_id, timestamp)
			VALUES ($1, $2, $3, $4) RETURNING id`

	err := db.QueryRow(query, ride.Distance, ride.CO2Saved, ride.UserID, ride.Timestamp).Scan(&ride.ID)
	return err
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS companies (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			company_id INTEGER REFERENCES companies(id)
		);
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS rides (
			id SERIAL PRIMARY KEY,
			distance FLOAT NOT NULL,
			co2_saved FLOAT NOT NULL,
			user_id INTEGER REFERENCES users(id),
			timestamp TIMESTAMP
		);
	`)
	return err
}

func insertUser(db *sql.DB, user User) (int, error) {
	query := `INSERT INTO users (first_name, last_name, company_id) VALUES ($1, $2, $3) RETURNING id`
	var id int
	err := db.QueryRow(query, user.FirstName, user.LastName, user.CompanyID).Scan(&id)
	return id, err
}

func openConnection() (*sql.DB, error) {
	connStr := "user=bikehunter password=menarche4reprove6muffin3pronged host=192.168.68.69 dbname=postgres sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	return db, err
}

func insertCompany(db *sql.DB, name string) (int, error) {
	query := `INSERT INTO companies (name) VALUES ($1) RETURNING id`
	var id int
	err := db.QueryRow(query, name).Scan(&id)
	return id, err
}

func storeUserIfNotExists(userInfo *LinkedInUserInfo) (int, error) {
	query := `INSERT INTO users (first_name, last_name, email, linkedin_id)
	          VALUES ($1, $2, $3, $4)
			  ON CONFLICT (linkedin_id) DO UPDATE
			  SET first_name = excluded.first_name,
			      last_name = excluded.last_name,
				  email = excluded.email
			  RETURNING id`

	var userID int
	err := db.QueryRow(query, userInfo.FirstName.Localized.EnUS, userInfo.LastName.Localized.EnUS, userInfo.Email.EmailAddress, userInfo.ID).Scan(&userID)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func randomInt(min, max int) int {
	bigIntMax := big.NewInt(int64(max - min))
	nBig, err := rand.Int(rand.Reader, bigIntMax)
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	return int(n) + min
}

func randomFloat64(min, max float64) float64 {
	bigIntMax := big.NewInt(1<<53 - 1)
	nBig, err := rand.Int(rand.Reader, bigIntMax)
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	f := float64(n) / float64(1<<53-1)
	return f*(max-min) + min
}

func createJWTTokenSimple(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(3600 * time.Hour).Unix(),
	})

	signedToken, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func generateJWTMoreInformation(user *User) (string, error) {
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set the claims for the token
	claims := token.Claims.(jwt.MapClaims)
	claims["firstName"] = user.FirstName
	claims["lastName"] = user.LastName
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	signedToken, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func getAllCompaniesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		companies, err := getAllCompanies()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(companies)
	}
}

func getAllCompanies() ([]Company, error) {
	query := "SELECT id, name, logo_url FROM companies"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var companies []Company
	for rows.Next() {
		var company Company
		err := rows.Scan(&company.ID, &company.Name, &company.LogoURL)
		if err != nil {
			return nil, err
		}
		companies = append(companies, company)
	}

	return companies, nil
}

func linkedinAuthHandler(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(16)
	authorizationURL := fmt.Sprintf("https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=r_liteprofile%%20r_emailaddress", clientID, url.QueryEscape(redirectURI), state)
	http.Redirect(w, r, authorizationURL, http.StatusTemporaryRedirect)
}

func findUserInDatabase(id int) (*User, error) {
	query := `SELECT id, first_name, last_name, company_id FROM users WHERE id = $1`

	user := &User{}
	err := db.QueryRow(query, id).Scan(&user.ID, &user.FirstName, &user.LastName, &user.CompanyID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func authenticateUser(user User) (string, error) {
	// Retrieve the user from the database
	dbUser, err := findUserInDatabase(user.ID)
	if err != nil {
		return "", err
	}

	// If the user exists in the database, generate a JWT token and return it
	token, err := generateJWTMoreInformation(dbUser)
	if err != nil {
		return "", err
	}

	return token, nil
}

func getLinkedInUserInfo(accessToken string) (*LinkedInUserInfo, error) {
	client := &http.Client{}
	// Request basic profile information
	profileReq, _ := http.NewRequest("GET", "https://api.linkedin.com/v2/me?projection=(id,firstName,lastName)", nil)
	profileReq.Header.Add("Authorization", "Bearer "+accessToken)
	profileResp, err := client.Do(profileReq)
	if err != nil {
		return nil, err
	}
	defer profileResp.Body.Close()

	profileData, err := ioutil.ReadAll(profileResp.Body)
	if err != nil {
		return nil, err
	}

	// Request email address
	emailReq, _ := http.NewRequest("GET", "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))", nil)
	emailReq.Header.Add("Authorization", "Bearer "+accessToken)
	emailResp, err := client.Do(emailReq)
	if err != nil {
		return nil, err
	}
	defer emailResp.Body.Close()

	emailData, err := ioutil.ReadAll(emailResp.Body)
	if err != nil {
		return nil, err
	}

	// Combine the profile and email data into a single JSON object
	var userInfo LinkedInUserInfo
	err = json.Unmarshal(append(profileData[:len(profileData)-1], []byte(`,"elements":`+string(emailData)+`}`)...), &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func createUser(firstName, lastName, linkedinID string) (int, error) {
	query := `INSERT INTO users (first_name, last_name, linkedin_id) VALUES ($1, $2, $3) RETURNING id`
	var userID int
	err := db.QueryRow(query, firstName, lastName, linkedinID).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}
func verifyTokenAndExtractClaims(tokenString string) (jwt.MapClaims, error) {
	// Parse the token string
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	// Check for errors and validate the token
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("Invalid token creation")
}

func linkedinCallbackHandler(w http.ResponseWriter, r *http.Request) {

	token := r.URL.Query().Get("token")
	if len(token) > 0 {

		time.Sleep(time.Second * 10)
		http.Error(w, "You got the token", http.StatusAccepted)
		return
	}

	code := r.URL.Query().Get("code")

	state := r.URL.Query().Get("state")
	user := new(User)

	a, err := requestAccessToken(code, state)

	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user information from LinkedIn API
	userInfo, err := getLinkedInUserInfo(a.AccessToken)

	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error fetching user information", http.StatusInternalServerError)
		return
	}

	fmt.Println("Linkedin Info: ", userInfo)
	linkedinID := userInfo.ID
	user, err = getUserByLinkedinID(linkedinID)
	if err != nil {
		fmt.Println("error getting userByLinkedInID", err)
	}
	fmt.Println("User based on linkedin login: ", user)
	if user == nil { // Check if the user is nil before creating a new user
		userID, err := createUser(userInfo.FirstName.Localized.EnUS, userInfo.LastName.Localized.EnUS, userInfo.ID)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "could not create user: +4746546996 to reach Sebastian", http.StatusInternalServerError)
			return
		}
		user = &User{
			ID: userID,
		}
		fmt.Println(userID, " ------------------- user created ---------------")
	}

	jwtToken, err := createJWTTokenSimple(user.ID)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to generate JWT token", http.StatusInternalServerError)
		return
	}

	callbackURL := fmt.Sprintf("%s?token=%s", redirectURI, jwtToken)
	w.Header().Set("Content-Type", "application/json")
	http.Redirect(w, r, callbackURL, http.StatusTemporaryRedirect)

}

func requestAccessToken(code, state string) (struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.linkedin.com/oauth/v2/accessToken", ioutil.NopCloser(strings.NewReader(data.Encode())))
	if err != nil {
		return struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}{}, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}{}, err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}{}, err
	}

	return result, nil
}

func generateRandomString(length int) string {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(buf)[:length]
}
