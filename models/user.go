package models

import "time"

type User struct {
    ID            int     `json:"id"`
    Fullname      string  `json:"fullname"`
    Address       string  `json:"address"`
    Telephone     string  `json:"telephone"`
    Email         string  `json:"email"`
    AccountNumber string  `json:"account_number"`
    AccountBalance float64 `json:"account_balance"`
    Password      string  `json:"-"`
}

type Beneficiary struct {
    ID            int    `json:"id"`
    Email         string `json:"email"`
    AccountNumber string `json:"account_number"`
    AccountName   string `json:"account_name"`
}

type Transaction struct {
    ID              int       `json:"id"`
    Email           string    `json:"email"`
    FromAccount     string    `json:"from_account"`
    ToAccount       string    `json:"to_account"`
    Amount          float64   `json:"amount"`
    TransactionType string    `json:"transaction_type"`
    Date            time.Time `json:"date"`
}