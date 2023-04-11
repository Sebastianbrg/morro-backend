package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type DistanceRequest struct {
	Distance float64 `json:"distance"`
	Company  string  `json:"company"`
}

var (
	clientID     string
	clientSecret string
	redirectURI  = "linkedin-auth://callback"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	clientID = os.Getenv("LINKEDIN_CLIENT_ID")
	clientSecret = os.Getenv("LINKEDIN_CLIENT_SECRET")
	redirectURI = os.Getenv("LINKEDIN_REDIRECT_URI")

	http.HandleFunc("/submit", submitHandler)
	http.HandleFunc("/auth/linkedin", linkedinAuthHandler)
	http.HandleFunc("/auth/linkedin/callback", linkedinCallbackHandler)
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))
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

func getRandomCompany() string {
	companies := []string{"Company A", "Company B", "Company C", "Company D", "Company E"}
	randSource := rand.NewSource(time.Now().UnixNano())
	randGen := rand.New(randSource)
	return companies[randGen.Intn(len(companies))]
}

func linkedinAuthHandler(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(16)
	authorizationURL := fmt.Sprintf("https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=r_liteprofile%%20r_emailaddress", clientID, url.QueryEscape(redirectURI), state)
	http.Redirect(w, r, authorizationURL, http.StatusTemporaryRedirect)

}

func linkedinCallbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Callback received with query: %s\n", r.URL.RawQuery)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	accessToken, err := requestAccessToken(code, state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Access Token: %s", accessToken)
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
