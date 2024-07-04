package handlers

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "math/rand"
    "net/http"
    "strconv"
    "time"
    "os"

    "github.com/dgrijalva/jwt-go"
    "golang.org/x/crypto/bcrypt"
    "github.com/gorilla/mux"
    "github.com/jung-kurt/gofpdf"
    "github.com/tealeg/xlsx"

    "banking-app/database"
    "banking-app/models"
)


var JwtKey = []byte("migospay")

type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

func Register(w http.ResponseWriter, r *http.Request) {
    var user models.User
    err := json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    user.Password = string(hashedPassword)
    user.AccountNumber = "2030" + fmt.Sprintf("%06d", rand.Intn(999999))
    user.AccountBalance = 0.00

    _, err = database.DB.Exec("INSERT INTO users (fullname, address, telephone, email, account_number, account_balance, password) VALUES (?, ?, ?, ?, ?, ?, ?)",
        user.Fullname, user.Address, user.Telephone, user.Email, user.AccountNumber, user.AccountBalance, user.Password)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with registration success message and registered user data
    response := struct {
        Message string     `json:"message"`
        User    models.User `json:"user"`
    }{
        Message: "Registration Successful",
        User:    user,
    }

    w.WriteHeader(http.StatusCreated) // HTTP 201 Created
    json.NewEncoder(w).Encode(response)
}

func Login(w http.ResponseWriter, r *http.Request) {
    var creds models.User
    err := json.NewDecoder(r.Body).Decode(&creds)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    var storedUser models.User
    err = database.DB.QueryRow("SELECT * FROM users WHERE email = ?", creds.Email).Scan(&storedUser.ID, &storedUser.Fullname, &storedUser.Address, &storedUser.Telephone, &storedUser.Email, &storedUser.AccountNumber, &storedUser.AccountBalance, &storedUser.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "User not found", http.StatusUnauthorized)
        } else {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(creds.Password))
    if err != nil {
        http.Error(w, "Invalid password", http.StatusUnauthorized)
        return
    }

    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Email: storedUser.Email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(JwtKey)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "Login successful",
        "token":   tokenString,
        "user":    storedUser,
    })
}

func CreateBeneficiary(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)

    var beneficiary models.Beneficiary
    err := json.NewDecoder(r.Body).Decode(&beneficiary)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    var userID int
    err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    _, err = database.DB.Exec("INSERT INTO beneficiaries (user_id, email, account_number, account_name) VALUES (?, ?, ?, ?)",
        userID, beneficiary.Email, beneficiary.AccountNumber, beneficiary.AccountName)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with Beneficiary Created message
    w.WriteHeader(http.StatusCreated) // HTTP 201 Created
    json.NewEncoder(w).Encode(map[string]string{"message": "Beneficiary Created"})
}

func UpdateBeneficiary(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid beneficiary ID", http.StatusBadRequest)
        return
    }

    var beneficiary models.Beneficiary
    err = json.NewDecoder(r.Body).Decode(&beneficiary)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    _, err = database.DB.Exec("UPDATE beneficiaries SET email = ?, account_number = ?, account_name = ? WHERE id = ?",
        beneficiary.Email, beneficiary.AccountNumber, beneficiary.AccountName, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with Beneficiary Updated message
    json.NewEncoder(w).Encode(map[string]string{"message": "Beneficiary Updated"})
}

func DeleteBeneficiary(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid beneficiary ID", http.StatusBadRequest)
        return
    }

    _, err = database.DB.Exec("DELETE FROM beneficiaries WHERE id = ?", id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"message": "Beneficiary deleted"})
}

func GetBeneficiaryByEmail(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)

    var beneficiaries []models.Beneficiary
    rows, err := database.DB.Query("SELECT id, email, account_number, account_name FROM beneficiaries WHERE user_id = (SELECT id FROM users WHERE email = ?)", userEmail)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    for rows.Next() {
        var beneficiary models.Beneficiary
        err := rows.Scan(&beneficiary.ID, &beneficiary.Email, &beneficiary.AccountNumber, &beneficiary.AccountName)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        beneficiaries = append(beneficiaries, beneficiary)
    }

    if err := rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Respond with Beneficiary Details
    json.NewEncoder(w).Encode(beneficiaries)
}

func Transfer(w http.ResponseWriter, r *http.Request, isBeneficiary bool) {
    type TransferRequest struct {
        FromAccount string  `json:"from_account"`
        ToAccount   string  `json:"to_account"`
        Amount      float64 `json:"amount"`
    }

    var transferReq TransferRequest
    err := json.NewDecoder(r.Body).Decode(&transferReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    tx, err := database.DB.Begin()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Deduct the amount from the sender's account
    _, err = tx.Exec("UPDATE users SET account_balance = account_balance - ? WHERE account_number = ?",
        transferReq.Amount, transferReq.FromAccount)
    if err != nil {
        tx.Rollback()
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Add the amount to the recipient's account
    _, err = tx.Exec("UPDATE users SET account_balance = account_balance + ? WHERE account_number = ?",
        transferReq.Amount, transferReq.ToAccount)
    if err != nil {
        tx.Rollback()
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    if err = tx.Commit(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Save the transaction
    userEmail := r.Context().Value("email").(string)
    transactionType := "debit"
    if isBeneficiary {
        transactionType = "credit"
    }
    _, err = database.DB.Exec("INSERT INTO transactions (email, from_account, to_account, amount, transaction_type) VALUES (?, ?, ?, ?, ?)",
        userEmail, transferReq.FromAccount, transferReq.ToAccount, transferReq.Amount, transactionType)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"message": "Transfer successful"})
}

func TransferToNonBeneficiary(w http.ResponseWriter, r *http.Request) {
    Transfer(w, r, false)
}

func TransferToBeneficiary(w http.ResponseWriter, r *http.Request) {
    Transfer(w, r, true)
}

func GetCreditTransactions(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)

    rows, err := database.DB.Query("SELECT id, email, from_account, to_account, amount, transaction_type, date FROM transactions WHERE email = ? AND transaction_type = 'credit'", userEmail)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var transactions []models.Transaction
    for rows.Next() {
        var transaction models.Transaction
        var date []byte
        if err := rows.Scan(&transaction.ID, &transaction.Email, &transaction.FromAccount, &transaction.ToAccount, &transaction.Amount, &transaction.TransactionType, &date); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transaction.Date, err = time.Parse("2006-01-02 15:04:05", string(date))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transactions = append(transactions, transaction)
    }
    if err := rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(transactions)
}

func GetDebitTransactions(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)

    rows, err := database.DB.Query("SELECT id, email, from_account, to_account, amount, transaction_type, date FROM transactions WHERE email = ? AND transaction_type = 'debit'", userEmail)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var transactions []models.Transaction
    for rows.Next() {
        var transaction models.Transaction
        var date []byte
        if err := rows.Scan(&transaction.ID, &transaction.Email, &transaction.FromAccount, &transaction.ToAccount, &transaction.Amount, &transaction.TransactionType, &date); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transaction.Date, err = time.Parse("2006-01-02 15:04:05", string(date))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transactions = append(transactions, transaction)
    }
    if err := rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(transactions)
}

func GetAllTransactions(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)

    rows, err := database.DB.Query("SELECT id, email, from_account, to_account, amount, transaction_type, date FROM transactions WHERE email = ?", userEmail)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var transactions []models.Transaction
    for rows.Next() {
        var transaction models.Transaction
        var date []byte
        if err := rows.Scan(&transaction.ID, &transaction.Email, &transaction.FromAccount, &transaction.ToAccount, &transaction.Amount, &transaction.TransactionType, &date); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transaction.Date, err = time.Parse("2006-01-02 15:04:05", string(date))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transactions = append(transactions, transaction)
    }
    if err := rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(transactions)
}

func GetTransactionsBetweenDates(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)
    fromDate := r.URL.Query().Get("from")
    toDate := r.URL.Query().Get("to")

    fromTime, err := time.Parse("2006-01-02", fromDate)
    if err != nil {
        http.Error(w, "Invalid from date format. Use YYYY-MM-DD", http.StatusBadRequest)
        return
    }

    toTime, err := time.Parse("2006-01-02", toDate)
    if err != nil {
        http.Error(w, "Invalid to date format. Use YYYY-MM-DD", http.StatusBadRequest)
        return
    }

    rows, err := database.DB.Query("SELECT id, email, from_account, to_account, amount, transaction_type, date FROM transactions WHERE email = ? AND date BETWEEN ? AND ?",
        userEmail, fromTime, toTime)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var transactions []models.Transaction
    for rows.Next() {
        var transaction models.Transaction
        var date []byte
        if err := rows.Scan(&transaction.ID, &transaction.Email, &transaction.FromAccount, &transaction.ToAccount, &transaction.Amount, &transaction.TransactionType, &date); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transaction.Date, err = time.Parse("2006-01-02 15:04:05", string(date))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transactions = append(transactions, transaction)
    }
    if err := rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(transactions)
}

func ExportTransactionsBetweenDates(w http.ResponseWriter, r *http.Request) {
    userEmail := r.Context().Value("email").(string)
    fromDate := r.URL.Query().Get("from")
    toDate := r.URL.Query().Get("to")

    fromTime, err := time.Parse("2006-01-02", fromDate)
    if err != nil {
        http.Error(w, "Invalid from date format. Use YYYY-MM-DD", http.StatusBadRequest)
        return
    }

    toTime, err := time.Parse("2006-01-02", toDate)
    if err != nil {
        http.Error(w, "Invalid to date format. Use YYYY-MM-DD", http.StatusBadRequest)
        return
    }

    rows, err := database.DB.Query("SELECT id, email, from_account, to_account, amount, transaction_type, date FROM transactions WHERE email = ? AND date BETWEEN ? AND ?",
        userEmail, fromTime, toTime)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var transactions []models.Transaction
    for rows.Next() {
        var transaction models.Transaction
        var date []byte
        if err := rows.Scan(&transaction.ID, &transaction.Email, &transaction.FromAccount, &transaction.ToAccount, &transaction.Amount, &transaction.TransactionType, &date); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transaction.Date, err = time.Parse("2006-01-02 15:04:05", string(date))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        transactions = append(transactions, transaction)
    }
    if err := rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Check if the request wants a PDF or XLSX export
    exportType := r.URL.Query().Get("export")
    switch exportType {
    case "pdf":
        generatePDF(transactions, w, r)
    case "xlsx":
        generateXLSX(transactions, w, r)
    default:
        // If no export type specified, return JSON
        json.NewEncoder(w).Encode(transactions)
    }
}

// generatePDF creates a PDF file with transaction details and writes it to the response
func generatePDF(transactions []models.Transaction, w http.ResponseWriter, r *http.Request) {
    pdf := gofpdf.New("P", "mm", "A4", "")
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(40, 10, "Transactions Report")

    pdf.Ln(10)

    // Table header
    pdf.SetFont("Arial", "B", 12)
    pdf.Cell(30, 7, "ID")
    pdf.Cell(40, 7, "Email")
    pdf.Cell(40, 7, "From Account")
    pdf.Cell(40, 7, "To Account")
    pdf.Cell(30, 7, "Amount")
    pdf.Cell(30, 7, "Type")
    pdf.Cell(30, 7, "Date")
    pdf.Ln(7)

    // Table rows
    pdf.SetFont("Arial", "", 12)
    for _, transaction := range transactions {
        pdf.CellFormat(30, 7, strconv.Itoa(transaction.ID), "1", 0, "", false, 0, "")
        pdf.CellFormat(40, 7, transaction.Email, "1", 0, "", false, 0, "")
        pdf.CellFormat(40, 7, transaction.FromAccount, "1", 0, "", false, 0, "")
        pdf.CellFormat(40, 7, transaction.ToAccount, "1", 0, "", false, 0, "")
        pdf.CellFormat(30, 7, strconv.FormatFloat(transaction.Amount, 'f', 2, 64), "1", 0, "", false, 0, "")
        pdf.CellFormat(30, 7, transaction.TransactionType, "1", 0, "", false, 0, "")
        pdf.CellFormat(30, 7, transaction.Date.Format("2006-01-02 15:04:05"), "1", 0, "", false, 0, "")
        pdf.Ln(7)
    }

    file, err := os.Create("transactions_report.pdf")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer file.Close()

    err = pdf.Output(file)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.ServeFile(w, r, "transactions_report.pdf")
}

// generateXLSX creates an XLSX file with transaction details and writes it to the response
func generateXLSX(transactions []models.Transaction, w http.ResponseWriter, r *http.Request) {
    file := xlsx.NewFile()
    sheet, err := file.AddSheet("Transactions")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Header row
    row := sheet.AddRow()
    row.AddCell().SetValue("ID")
    row.AddCell().SetValue("Email")
    row.AddCell().SetValue("From Account")
    row.AddCell().SetValue("To Account")
    row.AddCell().SetValue("Amount")
    row.AddCell().SetValue("Type")
    row.AddCell().SetValue("Date")

    // Data rows
    for _, transaction := range transactions {
        row = sheet.AddRow()
        row.AddCell().SetValue(strconv.Itoa(transaction.ID))
        row.AddCell().SetValue(transaction.Email)
        row.AddCell().SetValue(transaction.FromAccount)
        row.AddCell().SetValue(transaction.ToAccount)
        row.AddCell().SetValue(strconv.FormatFloat(transaction.Amount, 'f', 2, 64))
        row.AddCell().SetValue(transaction.TransactionType)
        row.AddCell().SetValue(transaction.Date.Format("2006-01-02 15:04:05"))
    }

    xlsxFileName := "transactions_report.xlsx"
    err = file.Save(xlsxFileName)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.ServeFile(w, r, xlsxFileName)
}