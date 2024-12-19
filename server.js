const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const app = express();
const session = require("express-session");
const mongoose = require("mongoose");
const methodOverride = require("method-override");
const morgan = require("morgan");

// Validate environment variables
if (!process.env.SESSION_SECRET || !process.env.MONGODB_URI) {
    console.error("Error: Missing required environment variables.");
    process.exit(1);
}

// Middleware for HTTP method override
app.use(methodOverride("_method"));

// Middleware for logging HTTP requests
app.use(morgan("dev"));

// Middleware for session handling
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);

// Middleware to parse URL-encoded data from forms
app.use(express.urlencoded({ extended: false }));

// Set the view engine for rendering EJS files
app.set("view engine", "ejs");

// Set the port from environment variable or default to 3000
const port = process.env.PORT || 3000;

// Controller imports
const authController = require("./controllers/auth.js");

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.connection.on("connected", () => {
    console.log(`Connected to MongoDB: ${mongoose.connection.name}.`);
});

mongoose.connection.on("error", (err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
});

// Routes
app.get("/", async (req, res) => {
    res.render("index.ejs", { user: req.session.user });
});

// VIP Lounge route
app.get("/vip-lounge", (req, res) => {
    if (req.session.user) {
        res.send(`Welcome to the party ${req.session.user.username}.`);
    } else {
        res.send("Sorry, no guests allowed.");
    }
});

// Use the auth controller for authentication routes
app.use("/auth", authController);

// Start the server
app.listen(port, () => {
    console.log(`The express app is ready on port ${port}!`);
});
