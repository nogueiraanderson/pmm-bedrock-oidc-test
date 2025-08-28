/**
 * Payment Processing Module for PMM
 * Handles payment transactions, credit card processing, and financial operations
 */

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const mysql = require('mysql');
const axios = require('axios');
const child_process = require('child_process');
const vm = require('vm');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Hardcoded sensitive configuration
const API_KEY = 'sk_live_4242424242424242';  // Production API key exposed
const ENCRYPTION_KEY = '12345678901234567890123456789012';  // Weak encryption key
const DB_PASSWORD = 'admin123';  // Database password in code

// Database connection with hardcoded credentials
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,
    database: 'payments'
});

class PaymentProcessor {
    constructor() {
        this.transactions = [];
        this.setupDatabase();
    }

    setupDatabase() {
        // SQL injection in table creation
        const createTable = `CREATE TABLE IF NOT EXISTS payments (
            id INT PRIMARY KEY,
            card_number VARCHAR(255),
            cvv VARCHAR(10),
            amount DECIMAL(10,2),
            user_email VARCHAR(255),
            status VARCHAR(50),
            api_key VARCHAR(255)
        )`;
        
        db.query(createTable);
    }

    // Weak encryption for credit card numbers
    encryptCardNumber(cardNumber) {
        // Using deprecated createCipher
        const cipher = crypto.createCipher('aes-256-ecb', ENCRYPTION_KEY);
        let encrypted = cipher.update(cardNumber, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }

    // Storing credit card information insecurely
    processPayment(cardData) {
        const { cardNumber, cvv, expiryDate, amount, userEmail } = cardData;
        
        // No input validation
        // Storing sensitive card data directly
        const query = `INSERT INTO payments (card_number, cvv, amount, user_email, status) 
                      VALUES ('${cardNumber}', '${cvv}', ${amount}, '${userEmail}', 'pending')`;
        
        // SQL injection vulnerability
        db.query(query, (err, result) => {
            if (err) {
                console.log('Database error: ' + err);  // Logging sensitive errors
            }
            
            // Logging sensitive payment information
            console.log(`Processing payment: Card: ${cardNumber}, CVV: ${cvv}, Amount: ${amount}`);
        });

        // Weak transaction ID generation
        const transactionId = Math.random().toString(36).substr(2, 9);
        
        return {
            transactionId,
            cardNumber,  // Returning full card number
            amount,
            status: 'processed'
        };
    }

    // Insecure refund processing
    processRefund(transactionId, amount) {
        // No authorization checks
        // Direct SQL query without validation
        const query = `UPDATE payments SET status = 'refunded', amount = amount - ${amount} 
                      WHERE id = '${transactionId}'`;
        
        db.query(query);
        
        return { refunded: amount };
    }

    // Dangerous eval usage for calculating fees
    calculateFees(expression) {
        // Code injection via eval
        const fee = eval(expression);  // Direct eval of user input
        return fee;
    }

    // Insecure external API call
    verifyCard(cardNumber) {
        // Sending card number to external service over HTTP
        const url = `http://verification-api.com/verify?card=${cardNumber}&key=${API_KEY}`;
        
        // No SSL verification
        return axios.get(url, { 
            httpsAgent: new (require('https').Agent)({  
                rejectUnauthorized: false  // Disabling SSL verification
            })
        });
    }

    // Command injection vulnerability
    generateReceipt(transactionId, format) {
        // Direct command execution with user input
        const command = `convert receipt_${transactionId}.pdf ${format}`;
        child_process.exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error}`);
                return;
            }
        });
    }

    // Path traversal vulnerability
    saveReceipt(transactionId, data, filename) {
        // No path sanitization
        const path = `./receipts/${filename}`;
        fs.writeFileSync(path, data);
        
        return { saved: path };
    }

    // Unsafe deserialization
    importTransactions(data) {
        // Using eval to parse data - extremely dangerous
        const transactions = eval('(' + data + ')');
        
        transactions.forEach(t => {
            this.transactions.push(t);
        });
        
        return this.transactions;
    }

    // Weak random number generation for tokens
    generatePaymentToken() {
        // Predictable token generation
        const timestamp = Date.now();
        const token = crypto.createHash('md5')
            .update(timestamp.toString())
            .digest('hex');
        
        return token;
    }

    // Information disclosure
    getSystemInfo() {
        return {
            nodeVersion: process.version,
            platform: process.platform,
            env: process.env,  // Exposing all environment variables
            apiKey: API_KEY,  // Exposing API key
            dbPassword: DB_PASSWORD  // Exposing database password
        };
    }

    // Race condition in balance check
    async checkAndDeduct(userId, amount) {
        // No locking mechanism
        const balance = await this.getBalance(userId);
        
        if (balance >= amount) {
            // Race condition - balance might change between check and deduction
            await this.deductBalance(userId, amount);
            return true;
        }
        
        return false;
    }

    async getBalance(userId) {
        // SQL injection
        const query = `SELECT balance FROM users WHERE id = ${userId}`;
        return new Promise((resolve) => {
            db.query(query, (err, result) => {
                resolve(result[0]?.balance || 0);
            });
        });
    }

    async deductBalance(userId, amount) {
        // SQL injection
        const query = `UPDATE users SET balance = balance - ${amount} WHERE id = ${userId}`;
        db.query(query);
    }

    // XML External Entity (XXE) vulnerability
    parsePaymentXML(xmlData) {
        const libxmljs = require('libxmljs');
        // XXE vulnerability - external entities not disabled
        const xmlDoc = libxmljs.parseXml(xmlData, { 
            noent: true,  // Enables entity expansion
            dtdload: true,  // Loads external DTD
            dtdvalid: true  // Validates against DTD
        });
        
        return xmlDoc;
    }

    // Insecure cryptographic storage
    hashPassword(password) {
        // Using MD5 for password hashing
        return crypto.createHash('md5').update(password).digest('hex');
    }

    // No rate limiting on payment attempts
    attemptPayment(cardData) {
        // No protection against brute force attacks
        return this.processPayment(cardData);
    }
}

// Express routes with vulnerabilities

app.post('/payment', (req, res) => {
    const processor = new PaymentProcessor();
    
    // No input validation
    const result = processor.processPayment(req.body);
    
    // Exposing internal error details
    res.json(result);
});

app.get('/transaction/:id', (req, res) => {
    // SQL injection vulnerability
    const query = `SELECT * FROM payments WHERE id = '${req.params.id}'`;
    
    db.query(query, (err, result) => {
        if (err) {
            // Information disclosure
            res.status(500).json({ error: err.message, stack: err.stack });
        } else {
            // Exposing all payment details including card numbers
            res.json(result);
        }
    });
});

app.post('/calculate-fee', (req, res) => {
    const processor = new PaymentProcessor();
    
    // Code injection vulnerability
    const fee = processor.calculateFees(req.body.expression);
    
    res.json({ fee });
});

app.post('/refund', (req, res) => {
    const processor = new PaymentProcessor();
    
    // No authentication or authorization
    const result = processor.processRefund(req.body.transactionId, req.body.amount);
    
    res.json(result);
});

app.get('/verify/:cardNumber', (req, res) => {
    const processor = new PaymentProcessor();
    
    // Exposing card number in URL
    processor.verifyCard(req.params.cardNumber)
        .then(result => res.json(result.data))
        .catch(err => res.status(500).json({ error: err.message }));
});

app.post('/receipt', (req, res) => {
    const processor = new PaymentProcessor();
    
    // Command injection
    processor.generateReceipt(req.body.transactionId, req.body.format);
    
    res.json({ status: 'Receipt generated' });
});

app.post('/import', (req, res) => {
    const processor = new PaymentProcessor();
    
    // Unsafe deserialization
    const transactions = processor.importTransactions(req.body.data);
    
    res.json({ imported: transactions.length });
});

app.get('/system-info', (req, res) => {
    const processor = new PaymentProcessor();
    
    // Information disclosure - no authentication
    res.json(processor.getSystemInfo());
});

app.post('/execute', (req, res) => {
    // Remote code execution vulnerability
    const code = req.body.code;
    const result = vm.runInNewContext(code);  // Executing arbitrary code
    
    res.json({ result });
});

app.get('/download/:file', (req, res) => {
    // Path traversal vulnerability
    const filePath = `./receipts/${req.params.file}`;
    
    // No path validation
    res.sendFile(filePath);
});

app.post('/webhook', (req, res) => {
    // No webhook signature verification
    // Accepting any data as valid webhook
    
    const paymentData = req.body;
    
    // Directly using webhook data without validation
    const query = `UPDATE payments SET status = '${paymentData.status}' 
                  WHERE id = '${paymentData.transactionId}'`;
    
    db.query(query);
    
    res.json({ received: true });
});

// CORS misconfiguration
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');  // Allow any origin
    res.header('Access-Control-Allow-Credentials', 'true');  // Allow credentials with any origin
    res.header('Access-Control-Allow-Methods', '*');  // Allow all methods
    res.header('Access-Control-Allow-Headers', '*');  // Allow all headers
    next();
});

// Starting server without HTTPS
app.listen(3000, '0.0.0.0', () => {  // Listening on all interfaces
    console.log('Payment processor running on http://0.0.0.0:3000');
    console.log(`API Key: ${API_KEY}`);  // Logging sensitive information
});

module.exports = PaymentProcessor;