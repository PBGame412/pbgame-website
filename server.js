const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

// Połączenie z bazą danych MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.log("Error connecting to MongoDB:", err));

// Schemat użytkownika
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Rejestracja użytkownika
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Wszystkie pola są wymagane!" });
    }

    try {
        // Sprawdzamy, czy użytkownik już istnieje
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Użytkownik już istnieje!" });
        }

        // Hashowanie hasła
        const hashedPassword = await bcrypt.hash(password, 10);

        // Tworzymy nowego użytkownika
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "Rejestracja zakończona pomyślnie!" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Błąd serwera!" });
    }
});

// Logowanie użytkownika
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Wszystkie pola są wymagane!" });
    }

    try {
        // Sprawdzamy, czy użytkownik istnieje
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: "Nieprawidłowe dane logowania!" });
        }

        // Sprawdzamy hasło
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Nieprawidłowe dane logowania!" });
        }

        // Tworzymy token JWT
        const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: "Zalogowano pomyślnie!", token });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Błąd serwera!" });
    }
});

// Uruchamiamy serwer
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
