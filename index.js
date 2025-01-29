import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";

dotenv.config(); // Load environment variables

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL Database setup with pg.Client
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DATABASE,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// Connect to the database
db.connect()
  .then(() => console.log("Connected to the database successfully"))
  .catch((err) => {
    console.error("Error connecting to the database:", err);
    process.exit(1);
  });

// Middleware
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === "production" },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport Strategies
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM loginmail WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (isPasswordValid) {
          return done(null, user);
        } else {
          return done(null, false, { message: "Incorrect password" });
        }
      } else {
        return done(null, false, { message: "User not found" });
      }
    } catch (err) {
      return done(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;
      const name = profile.displayName;
      try {
        const result = await db.query("SELECT * FROM loginmail WHERE email = $1", [email]);
        if (result.rows.length > 0) {
          return done(null, result.rows[0]);
        } else {
          const insertResult = await db.query(
            "INSERT INTO loginmail (email, name) VALUES ($1, $2) RETURNING *",
            [email, name]
          );
          return done(null, insertResult.rows[0]);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Serialize and Deserialize User
passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser(async (email, done) => {
  try {
    const result = await db.query("SELECT * FROM loginmail WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      done(null, result.rows[0]);
    } else {
      done(new Error("User not found"));
    }
  } catch (err) {
    done(err);
  }
});

// Routes
app.get("/", (req, res) => res.render("index.ejs"));

app.get("/booking", (req, res) => res.render("booking.ejs"));

app.get("/about", (req, res) => res.render("about.ejs"));

app.get("/FAQ", (req, res) => res.render("FAQ.ejs"));

app.get("/product", (req, res) => res.render("product.ejs"));

app.get("/profile", ensureAuthenticated, (req, res) => {
  res.render("profile.ejs", { user: req.user }); // Pass the user info to the profile page
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}


app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/profile");
  } else {
    res.render("login.ejs");
  }
});
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true, // If using flash messages
  }),
  (req, res) => {
    const returnTo = req.session.returnTo || "/profile";
    delete req.session.returnTo; // Clean up the session
    res.redirect(returnTo);
  }
);


app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/profile");
  }
);

app.get("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`Welcome ${req.user.name}`);
  } else {
    res.redirect("/login");
  }
});

app.post("/logout", (req, res) => {
  if (req.isAuthenticated()) {
    req.logout((err) => {
      if (err) {
        console.error("Error during logout:", err);
        res.send("Error logging out");
      } else {
        res.redirect("/login");
      }
    });
  } else {
    res.redirect("/login");
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something went wrong!");
});

// Start the Server
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
