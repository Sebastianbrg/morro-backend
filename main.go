package main

import (
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

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	clientID = os.Getenv("LINKEDIN_CLIENT_ID")
	clientSecret = os.Getenv("LINKEDIN_CLIENT_SECRET")
	redirectURI = os.Getenv("LINKEDIN_REDIRECT_URI")

	db, err := openConnection()
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}
	defer db.Close()

	err = createTables(db)
	if err != nil {
		log.Fatalf("Error creating companies table: %v", err)
	}

	err = generateSyntheticData(db) // Generate 5 companies, 50 users, and 200 rides
	if err != nil {
		log.Fatalf("Error generating synthetic data: %v", err)
	}

	data, err := getLeaderboard(db, 1)
	fmt.Println(data)
	if err != nil {
		log.Fatalf("Error getting leaderboard: %v", err)
	}

	http.HandleFunc("/submit", submitHandler)
	http.HandleFunc("/auth/linkedin", linkedinAuthHandler)
	http.HandleFunc("/auth/linkedin/callback", linkedinCallbackHandler)
	http.HandleFunc("/login", login)
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))

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

func generateJWT(user User) (string, error) {
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set the claims for the token
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
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

func getLeaderboard(db *sql.DB, companyID int) ([]map[string]interface{}, error) {
	query := `SELECT u.id, u.first_name, u.last_name, SUM(r.distance) as total_distance, SUM(r.co2_saved) as total_co2_saved
	          FROM users u
	          JOIN rides r ON u.id = r.user_id
	          WHERE u.company_id = $1
	          GROUP BY u.id
	          ORDER BY total_co2_saved DESC`

	rows, err := db.Query(query, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leaderboard []map[string]interface{}

	for rows.Next() {
		var id int
		var firstName, lastName string
		var totalDistance, totalCo2Saved float64

		err := rows.Scan(&id, &firstName, &lastName, &totalDistance, &totalCo2Saved)
		if err != nil {
			return nil, err
		}

		entry := map[string]interface{}{
			"id":            id,
			"firstName":     firstName,
			"lastName":      lastName,
			"totalDistance": totalDistance,
			"totalCo2Saved": totalCo2Saved,
		}
		leaderboard = append(leaderboard, entry)
	}

	return leaderboard, rows.Err()
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

func findUserInDatabase(id int) User {
	fmt.Println(id)

	return User{FirstName: "Not implemented"}
}

func authenticateUser(user User) (string, error) {
	// Retrieve the user from the database
	dbUser := findUserInDatabase(user.ID)

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

func linkedinCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	accessToken, err := requestAccessToken(code, state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	callbackURL := fmt.Sprintf("%s?access_token=%s", redirectURI, accessToken)
	http.Redirect(w, r, callbackURL, http.StatusTemporaryRedirect)
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
