package database

import (
    "database/sql"
    "log"

    _ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func ConnectDB() {
    var err error
    DB, err = sql.Open("mysql", "avnadmin:AVNS_QK_5Qr2G4q3mK8QSid-@tcp(mysql-1d10df7f-ozizichristopher712-96e0.f.aivencloud.com:11745)/banking_db")
    if err != nil {
        log.Fatal(err)
    }
    if err = DB.Ping(); err != nil {
        log.Fatal(err)
    }
    log.Println("Database connection established")
}
