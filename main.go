package main

import (
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "banking-app/database"
    "banking-app/handlers"
    "banking-app/auth"
)

func main() {
    database.ConnectDB()

    r := mux.NewRouter()

    r.HandleFunc("/register", handlers.Register).Methods("POST")
    r.HandleFunc("/login", handlers.Login).Methods("POST")

    s := r.PathPrefix("/api").Subrouter()
    s.Use(auth.VerifyToken) // Use VerifyToken as middleware directly

    s.HandleFunc("/beneficiary", handlers.CreateBeneficiary).Methods("POST")
    s.HandleFunc("/beneficiary/{id}", handlers.UpdateBeneficiary).Methods("PUT")
    s.HandleFunc("/beneficiary/{id}", handlers.DeleteBeneficiary).Methods("DELETE")
    s.HandleFunc("/beneficiary/email", handlers.GetBeneficiaryByEmail).Methods("GET")
    s.HandleFunc("/transfer", handlers.TransferToNonBeneficiary).Methods("POST")
    s.HandleFunc("/transfer-to-beneficiary", handlers.TransferToBeneficiary).Methods("POST")
    s.HandleFunc("/transactions/credit", handlers.GetCreditTransactions).Methods("GET")
    s.HandleFunc("/transactions/debit", handlers.GetDebitTransactions).Methods("GET")
    s.HandleFunc("/transactions/all", handlers.GetAllTransactions).Methods("GET")
    s.HandleFunc("/transactions/dates", handlers.GetTransactionsBetweenDates).Methods("GET") // New endpoint
    r.HandleFunc("/transactions/export", handlers.ExportTransactionsBetweenDates).Methods("GET")


    log.Println("Server is running on port 8000")
    log.Fatal(http.ListenAndServe(":8000", r))
}
