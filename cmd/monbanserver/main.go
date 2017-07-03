package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/kusubooru/monban/monban"
	"github.com/kusubooru/monban/rest"
	"github.com/kusubooru/shimmie/store"
)

var (
	httpAddr       = flag.String("http", ":8080", "HTTP listen address")
	driverName     = flag.String("driver", "mysql", "database driver")
	dataSourceName = flag.String("datasource", "", "database data source")
	secret         = flag.String("secret", "", "secret used to sign JWT tokens")
)

func main() {
	flag.Parse()
	if *secret == "" {
		log.Fatalln("No secret specified, exiting...")
	}
	if *dataSourceName == "" {
		log.Fatalln("No database datasource specified, exiting...")
	}
	s := store.Open(*driverName, *dataSourceName)
	authService := monban.NewAuthService(s, *secret)
	handlers := rest.NewServer(authService)

	log.Fatal(http.ListenAndServe(*httpAddr, handlers))
}
