package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	uuid "github.com/satori/go.uuid"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

func main() {
	key, secret := os.Args[1], os.Args[2]

	var scopes []string
	if len(os.Args) > 3 {
		for i := 3; i < len(os.Args); i++ {
			scopes = append(scopes, os.Args[i])
		}
	}

	claims := jws.Claims{}
	claims.SetJWTID(uuid.NewV4().String())
	claims.SetIssuer(key)

	if len(scopes) > 0 {
		claims.Set("scopes", scopes)
	}

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)

	data, err := token.Serialize([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}

	request, err := http.NewRequest("GET", "http://localhost:4040/api/auth", nil)
	if err != nil {
		log.Fatal(err)
	}

	request.Header.Set("Authorization", fmt.Sprintf("BEARER %s", string(data)))

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("status %s body %s\n", resp.Status, string(payload))
}
