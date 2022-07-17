package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	_ "goPosgres/main/zitifiedpq"

	"github.com/sirupsen/logrus"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "postgres"
	dbname   = "simpledb"
)

func main() {
	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	// open database
	db, err := sql.Open("zitifiedPostgresDriver", psqlconn)
	CheckError(err)

	// close database
	defer db.Close()

	// check db
	err = db.Ping()
	CheckError(err)

	fmt.Println("Connected!")
	rows, err := db.Query(`SELECT * FROM simpletable`)
	CheckError(err)

	defer rows.Close()
	for rows.Next() {
		var name string
		var roll int

		err = rows.Scan(&name, &roll)
		CheckError(err)

		fmt.Println(name, roll)
	}
}

func CheckError(err error) {
	if err != nil {
		logrus.Error(err)
	}
}
