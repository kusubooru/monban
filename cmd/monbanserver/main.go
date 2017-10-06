package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/kusubooru/monban/monban"
	"github.com/kusubooru/monban/monban/boltdb"
	"github.com/kusubooru/monban/monban/mysql"
	"github.com/kusubooru/monban/rest"
	"github.com/kusubooru/shimmie/store"
)

var (
	httpAddr           = flag.String("http", ":8080", "HTTP listen address")
	driverName         = flag.String("driver", "mysql", "monban database driver")
	dataSourceName     = flag.String("datasource", "", "monban database data source")
	shimmieDriver      = flag.String("shimmiedriver", "mysql", "shimmie database driver")
	shimmieDataSource  = flag.String("shimmiedatasource", "", "shimmie database data source")
	secret             = flag.String("secret", "", "secret used to sign JWT tokens")
	boltFile           = flag.String("boltfile", "monban.db", "BoltDB database file to store token whitelist")
	monbanIssuer       = flag.String("issuer", "monban", "will appear as the issuer field for created tokens")
	accessTokenMinutes = flag.Int64("atmins", 15, "minutes for access token to expire")
	refreshTokenHours  = flag.Int64("rthours", 72, "hours for the refresh token to expire")
)

func main() {
	flag.Parse()
	if *secret == "" {
		log.Fatalln("No secret specified, exiting...")
	}
	if *shimmieDataSource == "" {
		log.Fatalln("No shimmie database datasource specified, exiting...")
	}
	if *dataSourceName == "" {
		log.Fatalln("No database datasource specified, exiting...")
	}
	if *monbanIssuer == "" {
		log.Fatalln("No issuer specified, exiting...")
	}

	accessTokenDuration := time.Duration(*accessTokenMinutes) * time.Minute
	refreshTokenDuration := time.Duration(*refreshTokenHours) * time.Hour
	if accessTokenDuration <= 0 || refreshTokenDuration <= 0 {
		log.Fatalln("Token duration cannot be zero or negative, exiting...")
	}

	// Connect to monban db.
	monbanDB, err := mysql.OpenMonbanDB(*dataSourceName)
	if err != nil {
		log.Fatalln("Connection to monban db failed:", err)
	}
	defer func() {
		if err := monbanDB.Close(); err != nil {
			log.Println("Close monbanDB failed:", err)
		}
	}()

	// Connect to shimmie db.
	shimmieDB := store.Open(*shimmieDriver, *shimmieDataSource)

	// Boltdb whitelist.
	wl := boltdb.NewWhitelist(*boltFile)
	defer func() {
		if err := wl.Close(); err != nil {
			log.Println("whitelist close failed:", err)
		}
	}()
	startWhitelistReap(wl, refreshTokenDuration)

	// Inject dependencies to monban.
	authService := monban.NewAuthService(
		monbanDB,
		shimmieDB,
		wl,
		accessTokenDuration,
		refreshTokenDuration,
		*monbanIssuer,
		*secret,
	)
	handlers := rest.NewServer(authService)

	closeOnSignal(monbanDB, wl)
	if err := http.ListenAndServe(*httpAddr, handlers); err != nil {
		log.Println("server stopped:", err)
	}
}

func closeOnSignal(monbanDB *mysql.MonbanDB, wl monban.Whitelist) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for sig := range c {
			log.Printf("%v signal received, releasing database resources and exiting...", sig)
			if err := wl.Close(); err != nil {
				log.Println("bolt close failed:", err)
			}
			if err := monbanDB.Close(); err != nil {
				log.Println("monbanDB close failed:", err)
			}
			os.Exit(1)
		}
	}()
}

func startWhitelistReap(wl monban.Whitelist, duration time.Duration) {
	go func() {
		if err := wl.Reap(duration); err != nil {
			log.Printf("whitelist reap failed: %v", err)
		}
	}()
}
