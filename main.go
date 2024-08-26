package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Logger for demo service
var Logger = log.New(os.Stdout, "", log.LUTC|log.LstdFlags)

// Configuration loaded from environment variables
type Configuration struct {
	AppID    string `env:"DEMO_OAUTH2_APPID,required" json:"DEMO_OAUTH2_APPID"`
	Secret   string `env:"DEMO_OAUTH2_SECRET,required" json:"-"`
	Provider string `env:"DEMO_OIDC_PROVIDER,required" json:"DEMO_OIDC_PROVIDER"`
	Endpoint string `env:"DEMO_ENDPOINT_ADDR,required" json:"DEMO_ENDPOINT_ADDR"`
}

// IndexData provides data for the index template
type IndexData struct {
	Config Configuration
}

// CallbackData provides data for the callback template
type CallbackData struct {
	Token  string
	Claims string
}

var configuration Configuration

//go:embed templates/*
var templateFS embed.FS
var templates *template.Template

// RequestLogger wraps an http.Handler with minimal access logging
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)
		Logger.Println(r.Method, r.URL, r.ContentLength, time.Since(start), r.RemoteAddr)
	})
}

// ReadRandom reads a random string
func ReadRandom(len int) (string, error) {
	buf := make([]byte, len)
	_, err := rand.Read(buf)

	return hex.EncodeToString(buf), err
}

func init() {
	err := env.Parse(&configuration)
	if err != nil {
		panic(err)
	}

	templates, err = template.ParseFS(templateFS, "templates/*")
	if err != nil {
		panic(err)
	}
}

func main() {
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	confstr, _ := json.Marshal(configuration)
	Logger.Println("Loaded environment configuration", string(confstr))

	// Validate DEMO_ENDPOINT_ADDR URL
	endpoint, err := url.Parse(configuration.Endpoint)
	if err != nil {
		panic(err)
	}

	provider, err := oidc.NewProvider(ctx, configuration.Provider)
	if err != nil {
		panic(err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: configuration.AppID})

	authorization := oauth2.Config{
		ClientID:     configuration.AppID,
		ClientSecret: configuration.Secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  endpoint.JoinPath("oidc/callback").String(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	http.Handle("GET /", http.FileServer(http.Dir("static")))

	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		err := templates.ExecuteTemplate(w, "index.tmpl.html", IndexData{configuration})

		if err != nil {
			panic(err)
		}
	})

	http.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth2.authorization",
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: true,
		})

		err := templates.ExecuteTemplate(w, "logout.tmpl.html", nil)
		if err != nil {
			panic(err)
		}
	})

	http.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		state, err := ReadRandom(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		nonce, err := ReadRandom(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth2.state",
			Value:    state,
			HttpOnly: true,
			Path:     "/",
			MaxAge:   3600,
		})

		http.Redirect(w, r, authorization.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	http.HandleFunc("GET /oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()

		state, err := r.Cookie("oauth2.state")
		if err != nil {
			http.Error(w, "Missing state cookie", http.StatusBadRequest)
			return
		}

		if params.Get("state") != state.Value {
			http.Error(w, "Invalid state from oauth provider", http.StatusBadRequest)
			return
		}

		authtoken, err := authorization.Exchange(ctx, params.Get("code"))
		if err != nil {
			http.Error(w, "Failed to retrieve authorization token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		idtoken, ok := authtoken.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Authorization token does not contain an id_token field", http.StatusBadRequest)
			return
		}

		id, err := verifier.Verify(ctx, idtoken)
		if err != nil {
			http.Error(w, "ID token authorization failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		var claims json.RawMessage
		err = id.Claims(&claims)
		if err != nil {
			http.Error(w, "Failed to parse ID Token claims: "+err.Error(), http.StatusBadRequest)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth2.state",
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth2.authorization",
			Value:    authtoken.AccessToken,
			Expires:  authtoken.Expiry,
			Path:     "/",
			HttpOnly: true,
		})

		err = templates.ExecuteTemplate(w, "callback.tmpl.html", CallbackData{idtoken, string(claims)})
		if err != nil {
			panic(err)
		}
	})

	server := http.Server{Handler: RequestLogger(http.DefaultServeMux), Addr: ":9867"}
	go server.ListenAndServe()

	Logger.Println("Listening on :9867")
	<-ctx.Done()

	Logger.Println("Stopping service")
	server.Shutdown(context.Background())

	Logger.Println("Good bye!")
}
