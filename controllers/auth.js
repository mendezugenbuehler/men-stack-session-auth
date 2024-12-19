const express = require("express");
const router = express.Router();
const User = require("../models/user.js");
const bcrypt = require("bcrypt");

module.exports = router;

// Render the sign-up page
router.get("/sign-up", (req, res) => {
    res.render("auth/sign-up.ejs", { error: null });
});

// Handle sign-up form submission
router.post("/sign-up", async (req, res) => {
    try {
        // Check if the username is already taken
        const userInDatabase = await User.findOne({ username: req.body.username });
        if (userInDatabase) {
            return res.render("auth/sign-up.ejs", { error: "Username already taken." });
        }

        // Validate passwords match
        if (req.body.password !== req.body.confirmPassword) {
            return res.render("auth/sign-up.ejs", { error: "Passwords must match." });
        }

        // Hash the password securely
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Create and save the new user in the database
        const user = await User.create({
            username: req.body.username,
            password: hashedPassword,
        });

        // Send success message or redirect to sign-in page
        res.redirect("/auth/sign-in");
    } catch (error) {
        console.error("Error during sign-up:", error);
        res.status(500).send("Internal Server Error");
    }
});

// Render the sign-in page
router.get("/sign-in", (req, res) => {
    res.render("auth/sign-in.ejs", { error: null });
});

// Handle sign-in form submission
router.post("/sign-in", async (req, res) => {
    try {
        // Find the user in the database
        const userInDatabase = await User.findOne({ username: req.body.username });
        if (!userInDatabase) {
            return res.render("auth/sign-in.ejs", { error: "Login failed. Please try again." });
        }

        // Validate the user's password using bcrypt
        const validPassword = await bcrypt.compare(
            req.body.password,
            userInDatabase.password
        );
        if (!validPassword) {
            return res.render("auth/sign-in.ejs", { error: "Login failed. Please try again." });
        }

        // Store user information in the session
        req.session.user = {
            username: userInDatabase.username,
            _id: userInDatabase._id,
        };

        // Redirect to the home page on successful login
        res.redirect("/");
    } catch (error) {
        console.error("Error during sign-in:", error);
        res.status(500).send("Internal Server Error");
    }
});

// Handle sign-out
router.get("/sign-out", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error during sign-out:", err);
            return res.status(500).send("Failed to sign out. Please try again.");
        }
        res.redirect("/");
    });
});
