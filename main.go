package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type DistanceRequest struct {
	Distance float64 `json:"distance"`
	Company  string  `json:"company"`
}

var (
	clientID     string
	clientSecret string
	redirectURI  string
)

func initDB() {

}

var db *sql.DB
var rdb *redis.Client
var ctx = context.Background()

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

	http.HandleFunc("/submit", submitHandler)
	http.HandleFunc("/auth/linkedin", linkedinAuthHandler)
	http.HandleFunc("/auth/linkedin/callback", linkedinCallbackHandler)
	http.HandleFunc("/login", login)
	http.Handle("/user/stats/", http.StripPrefix("/user/stats/", http.HandlerFunc(handleGetUserStats)))
	http.Handle("/company/stats/", http.StripPrefix("/company/stats/", http.HandlerFunc(handleGetCompanyStats)))
	http.HandleFunc("/company/leaderboard/", handleGetLeaderboard)

	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))

}

type UserSession struct {
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

func storeUserSession(userSession *UserSession) error {
	jsonData, err := json.Marshal(userSession)
	if err != nil {
		return err
	}
	return rdb.Set(ctx, fmt.Sprintf("user_session:%d", userSession.UserID), jsonData, 0).Err()
}

func getUserSession(userID int) (*UserSession, error) {
	jsonData, err := rdb.Get(ctx, fmt.Sprintf("user_session:%d", userID)).Bytes()
	if err != nil {
		return nil, err
	}
	var userSession UserSession
	err = json.Unmarshal(jsonData, &userSession)
	if err != nil {
		return nil, err
	}
	return &userSession, nil
}

func handleGetLeaderboard(w http.ResponseWriter, r *http.Request) {
	leaderboard, err := getLeaderboard()
	if err != nil {
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

func getCompanyStats(companyID int) (CompanyStats, error) {
	var stats CompanyStats
	query := `
		SELECT SUM(rides.distance) AS total_distance, SUM(rides.co2_saved) AS total_co2_saved
		FROM rides
		INNER JOIN users ON users.id = rides.user_id
		WHERE users.company_id = $1;
	`

	err := db.QueryRow(query, companyID).Scan(&stats.TotalDistance, &stats.TotalCO2Saved)
	if err != nil {
		return CompanyStats{}, err
	}

	return stats, nil
}

func handleGetCompanyStats(w http.ResponseWriter, r *http.Request) {
	companyIDStr := strings.TrimPrefix(r.URL.Path, "/company/stats/")

	companyID, err := strconv.Atoi(companyIDStr)
	if err != nil {
		http.Error(w, "Invalid company ID", http.StatusBadRequest)
		return
	}

	stats, err := getCompanyStats(companyID)
	if err != nil {
		http.Error(w, "Error retrieving company stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

type CompanyStats struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	TotalDistance float64 `json:"total_distance"`
	TotalCO2Saved float64 `json:"total_co2_saved"`
}

type UserStats struct {
	TotalDistance float64 `json:"total_distance"`
	TotalCO2Saved float64 `json:"total_co2_saved"`
}

func handleGetUserStats(w http.ResponseWriter, r *http.Request) {
	// Remove the "/user/stats/" prefix from the path
	userIDStr := strings.TrimPrefix(r.URL.Path, "/user/stats/")

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	stats, err := getUserStats(userID)
	if err != nil {
		http.Error(w, "Error retrieving user stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func getUserStats(userID int) (UserStats, error) {
	var userStats UserStats
	var err error

	// Replace with your actual DB connection and query execution
	err = db.QueryRow("SELECT SUM(distance), SUM(co2_saved) FROM rides WHERE user_id = $1", userID).Scan(&userStats.TotalDistance, &userStats.TotalCO2Saved)

	if err != nil {
		return UserStats{}, err
	}

	return userStats, nil
}

func randFloat(reader io.Reader) (float64, error) {
	max := 1 << 53
	bigInt, err := rand.Int(reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return float64(bigInt.Int64()) / float64(max), nil
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
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

	req.Company = getRandomCompany()

	log.Printf("Received data: distance=%.2f, company=%s", req.Distance, req.Company)
	w.WriteHeader(http.StatusCreated)
}

type Ride struct {
	ID        int
	UserID    int
	Distance  float64
	CO2Saved  float64
	Timestamp time.Time
}

func insertRide(db *sql.DB, ride Ride) (int, error) {
	query := `INSERT INTO rides (user_id, distance, co2_saved, timestamp) VALUES ($1, $2, $3, $4) RETURNING id`
	var id int
	err := db.QueryRow(query, ride.UserID, ride.Distance, ride.CO2Saved, time.Now().Add(time.Duration(randomInt(-30, 0))*24*time.Hour)).Scan(&id)
	return id, err
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

type User struct {
	ID        int
	FirstName string
	LastName  string
	CompanyID int
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

func generateSyntheticData(db *sql.DB) error {
	companyNames := []string{"Company A", "Company B", "Company C", "Company D", "Company E"}
	var companyIDs []int

	for _, companyName := range companyNames {
		companyID, err := insertCompany(db, companyName)
		if err != nil {
			return fmt.Errorf("Error inserting company: %v", err)
		}
		companyIDs = append(companyIDs, companyID)
	}

	for i := 0; i < 100; i++ {
		user := User{
			FirstName: fmt.Sprintf("User%d", i+1),
			LastName:  "Doe",
			CompanyID: companyIDs[randomInt(0, len(companyIDs))],
		}
		userID, err := insertUser(db, user)
		if err != nil {
			return fmt.Errorf("Error inserting user: %v", err)
		}

		for j := 0; j < 10; j++ {
			ride := Ride{
				UserID:    userID,
				Distance:  randomFloat64(1, 20),
				CO2Saved:  randomFloat64(0.5, 5),
				Timestamp: time.Now().Add(time.Duration(randomInt(-30, 0)) * 24 * time.Hour),
			}
			_, err := insertRide(db, ride)
			if err != nil {
				return fmt.Errorf("Error inserting ride: %v", err)
			}
		}
	}

	return nil
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

func generateJWT(user *User) (string, error) {
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set the claims for the token
	claims := token.Claims.(jwt.MapClaims)
	claims["firstName"] = user.FirstName
	claims["lastName"] = user.LastName
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Sign the token using a secret key
	secretKey := []byte("your_secret_key")
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func getRandomCompany() string {
	companies := []string{"Company A", "Company B", "Company C", "Company D", "Company E"}

	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(companies))))
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()

	return companies[n]
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
	token, err := generateJWT(dbUser)
	if err != nil {
		return "", err
	}

	return token, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Get the user information from the request body
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Authenticate the user and generate a JWT token
	token, err := authenticateUser(user)
	if err != nil {
		// Return an error response if the authentication fails
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Return the JWT token in the response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token})

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

func linkedinCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	accessToken, err := requestAccessToken(code, state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user information from LinkedIn API
	userInfo, err := getLinkedInUserInfo(accessToken)
	if err != nil {
		http.Error(w, "Error fetching user information", http.StatusInternalServerError)
		return
	}

	// Create a UserSession and store it in Redis
	userSession := &UserSession{
		FirstName:           userInfo.FirstName.Localized.EnUS,
		LastName:            userInfo.LastName.Localized.EnUS,
		Email:               userInfo.Email.EmailAddress,
		LinkedInID:          userInfo.ID,
		LinkedInAccessToken: accessToken,
		// Fill in other fields as needed
	}
	err = storeUserSession(userSession)
	if err != nil {
		http.Error(w, "Error storing user session", http.StatusInternalServerError)
		return
	}

	callbackURL := fmt.Sprintf("%s?access_token=%s", redirectURI, accessToken)
	http.Redirect(w, r, callbackURL, http.StatusTemporaryRedirect)
	// Return the user information instead of the access token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userSession)
}

func requestAccessToken(code, state string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.linkedin.com/oauth/v2/accessToken", ioutil.NopCloser(strings.NewReader(data.Encode())))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result.AccessToken, nil
}

func generateRandomString(length int) string {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(buf)[:length]
}
