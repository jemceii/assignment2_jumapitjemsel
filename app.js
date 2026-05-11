require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").MongoStore;
const bcrypt = require("bcrypt");
const saltRounds = 12;

const app = express();

const Joi = require("joi");

const PORT = process.env.PORT || 3018;

const expireTime = 1 * 60 * 60 * 1000;
// Expire time 1 hour in milliseconds
// hours * minutes * seconds * milliseconds

// Secret Information
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
//

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.set("view engine", "ejs");
app.use(express.static("public"));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

//--middleware--//

const isLoggedIn = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
};

const isAdmin = (req, res, next) => {
  if (req.session && req.session.user_type === "admin") {
    return next();
  }
  res.status(403).render("admin", {
    title: "Admin Page",
    users: null,
    errorMessage: "You are not authorized to view this page.",
  });
};

//------//

// Main Page
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    res.render("app", {
      allowed: true,
      user: req.session.username,
      title: "App",
    });
  } else {
    res.render("app", { allowed: false, title: "Main" });
  }
});

// Members Page
app.get("/members", isLoggedIn, (req, res) => {
  // pass check, welcome
  const user = req.session.username;

  const images = ["cat1.gif", "cat2.gif", "cat3.gif"];
  const type = images[Math.floor(Math.random() * images.length)];

  res.render("members", { user, type, title: "Members" });
});

// Admin Page
app.get("/admin", isLoggedIn, isAdmin, async (req, res) => {
  const users = await userCollection.find().toArray();
  res.render("admin", { title: "Admin Page", users, errorMessage: null });
});

app.get("/demoteUser", isAdmin, async (req, res) => {
  const email = req.query.email;
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    res.redirect("/admin");
    return;
  }
  
  await userCollection.updateOne(
    { email: email },
    { $set: { user_type: "user" } }
  );
  res.redirect("/admin");
});

app.get("/promoteUser", isAdmin, async (req, res) => {
  const email = req.query.email;

  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    res.redirect("/admin");
    return;
  }

  await userCollection.updateOne(
    { email: email },
    { $set: { user_type: "admin" } }
  );
  res.redirect("/admin");
});

// Signing Up
app.get("/signup", (req, res) => {
  res.render("signup", { title: "Sign Up", errorMessage: null });
});

app.post("/signupSubmit", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  if (!username) {
    res.render("signup", {
      errorMessage: "Name is required.",
      title: "Sign Up",
    });
    return;
  }

  if (!email) {
    res.render("signup", {
      errorMessage: "Please provide an email address.",
      title: "Sign Up",
    });
    return;
  }

  if (!password) {
    res.render("signup", {
      errorMessage: "Password is required.",
      title: "Sign Up",
    });
    return;
  }

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });

  if (validationResult.error != null) {
    res.render("signup", {
      errorMessage: validationResult.error.details[0].message,
      title: "Sign Up",
    });
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username,
    email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.authenticated = true;
  req.session.username = username;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

// End of Signing Up

// Logging in
app.get("/login", (req, res) => {
  res.render("login", { title: "Log In", errorMessage: null });
});

app.post("/loginSubmit", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("login", {
      title: "Log In",
      errorMessage: "Invalid email/password combination.",
    });
    return;
  }

  const userResult = await userCollection.findOne({ email: email });

  if (!userResult) {
    console.log("user not found");
    res.render("login", {
      title: "Log In",
      errorMessage: "Invalid email/password combination.",
    });
    return;
  }

  if (await bcrypt.compare(password, userResult.password)) {
    req.session.authenticated = true;
    req.session.username = userResult.username;
    req.session.cookie.maxAge = expireTime;
    req.session.user_type = userResult.user_type;
    res.redirect("/members");
  } else {
    res.render("login", {
      title: "Log In",
      errorMessage: "Invalid email/password combination.",
    });
  }
});

// End of Logging in

// Log out
app.get("/logout", (req, res) => {
  req.session.destroy();

  res.redirect("/");
});

//------//
app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.render("404", { title: "Error 404" });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
