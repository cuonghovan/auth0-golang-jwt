package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/graphql-go/graphql"
)

type User struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Blog struct {
	Id        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Author    string `json:"author"`
	Pageviews int32  `json:"pageviews"`
}

var jwtSecret []byte = []byte("thepolyglotdeveloper")

var accountsMock []User = []User{
	User{
		Id:       "1",
		Username: "nraboy",
		Password: "1234",
	},
	User{
		Id:       "2",
		Username: "mraboy",
		Password: "5678",
	},
}

var blogsMock []Blog = []Blog{
	Blog{
		Id:        "1",
		Author:    "nraboy",
		Title:     "Sample Article",
		Content:   "This is a sample article written by Nic Raboy",
		Pageviews: 1000,
	},
}

var accountType *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Account",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"username": &graphql.Field{
			Type: graphql.String,
		},
		"password": &graphql.Field{
			Type: graphql.String,
		},
	},
})

var blogType *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Blog",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"title": &graphql.Field{
			Type: graphql.String,
		},
		"content": &graphql.Field{
			Type: graphql.String,
		},
		"author": &graphql.Field{
			Type: graphql.String,
		},
		"pageviews": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				_, err := ValidateJWT(params.Context.Value("token").(string))
				if err != nil {
					return nil, err
				}
				return params.Source.(Blog).Pageviews, nil
			},
		},
	},
})

func ValidateJWT(t string) (interface{}, error) {
	if t == "" {
		return nil, errors.New("Authorization token must be present")
	}
	token, _ := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return jwtSecret, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("claims", claims)
		// TODO: Return user where userid is the same in claims
		return accountsMock[1], nil
	} else {
		return nil, errors.New("Invalid authorization token")
	}
}

func CreateToken(user User) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
	})
	tokenString, error := token.SignedString(jwtSecret)
	if error != nil {
		fmt.Println(error)
	}
	return tokenString
}

func Login(response http.ResponseWriter, request *http.Request) {
	var user User
	_ = json.NewDecoder(request.Body).Decode(&user)
	// TODO: validate username, password  before generate token.

	token := CreateToken(user)
	response.Header().Set("content-type", "application/json")
	response.Write([]byte(`{ "token": "` + token + `" }`))
}

func main() {
	fmt.Println("Starting the application at :12345...")
	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"account": &graphql.Field{
				Type: accountType,
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					account, err := ValidateJWT(params.Context.Value("token").(string))
					if err != nil {
						return nil, err
					}
					return account, nil
				},
			},
			"blogs": &graphql.Field{
				Type: graphql.NewList(blogType),
				Resolve: func(params graphql.ResolveParams) (interface{}, error) {
					return blogsMock, nil
				},
			},
		},
	})
	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query: rootQuery,
	})
	http.HandleFunc("/graphql", func(response http.ResponseWriter, request *http.Request) {
		result := graphql.Do(graphql.Params{
			Schema:        schema,
			RequestString: request.URL.Query().Get("query"),
			Context:       context.WithValue(context.Background(), "token", request.URL.Query().Get("token")),
		})
		json.NewEncoder(response).Encode(result)
	})
	http.HandleFunc("/login", Login)
	http.ListenAndServe(":12345", nil)
}
