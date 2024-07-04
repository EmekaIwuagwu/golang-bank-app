package database

import (
    "database/sql"
    "log"

    _ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func ConnectDB() {
    var err error
    DB, err = sql.Open("mysql", "root:@tcp(localhost:3306)/banking_db")
    if err != nil {
        log.Fatal(err)
    }
    if err = DB.Ping(); err != nil {
        log.Fatal(err)
    }
    log.Println("Database connection established")
}
