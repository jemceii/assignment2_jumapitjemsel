require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").MongoStore;
const bcrypt = require("bcrypt");
const saltRounds = 12;

const app = express();

const Joi = require("joi");

const PORT = process.env.PORT || 3000;

const expireTime = 1 * 60 * 60 * 1000;
// Expire time 1 hour in milliseconds
// hours * minutes * seconds * milliseconds

// Secret Information
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
//

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
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

//------//

// Main Page
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    res.send(`
      Hello, ${req.session.username}!
      <br>
      <a href="/members"><button>Go to Members Area</button></a>
      <br>
      <a href="/logout"><button>Logout</button></a>
    `);
  } else {
    res.send(`
        <a href="/signup">Sign up</a>
        <br>
        <a href="/login">Log in</a>
    `);
  }
});

// Members Page
app.get("/members", (req, res) => {
  // check if user is a member
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  // pass check, welcome
  const user = req.session.username;

  const images = ["cat1.gif", "cat2.gif", "cat3.gif"];
  const type = images[Math.floor(Math.random() * images.length)];

  res.send(`
        <h1>Hello, ${user}.</h1>
        <br>
        <form action='/logout' method='get'>
            <img src="/${type}" alt="catgif" width="300">
            <br>
            <button>Sign out</button>
        </form>
    `);
});

// Signing Up
app.get("/signup", (req, res) => {
  var html = `
    create user
    <form action='/signupSubmit' method='post'>
        <input name='username' type='text' placeholder='username'>
        <br>
        <input name='email' type='email' placeholder='email'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/signupSubmit", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  if (!username) {
    res.send(`
            <p>Name is required.</p>
            <a href="/signup">Try again</a>
        `);
    return;
  }

  if (!email) {
    res.send(`
            <p>Please provide an email address.</p>
            <a href="/signup">Try again</a>
        `);
    return;
  }

  if (!password) {
    res.send(`
            <p>Password is required.</p>
            <a href="/signup">Try again</a>
        `);
    return;
  }

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
  });

  console.log("Inserted user");

  // created sessions
  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

// End of Signing Up

// Logging in
app.get("/login", (req, res) => {
  var html = `
    log in
    <form action='/loginSubmit' method='post'>
        <input name='email' type='email' placeholder='email'>
        </br>
        <input name='password' type='password' placeholder='password'>
        </br>
        <button>Submit</button>
    </form>
    `;
  res.send(html);
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
    res.redirect("/login");
    return;
  }

  const userResult = await userCollection.findOne({ email: email });

  if (!userResult) {
    console.log("user not found");
    res.send(
      `Invalid email/password combination. <br> <a href='/login'>Try again</a>`,
    );
    return;
  }

  // if password matches
  if (await bcrypt.compare(password, userResult.password)) {
    // create sessions
    req.session.authenticated = true;
    req.session.username = userResult.username;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } else {
    res.send(
      `Invalid email/password combination. <br> <a href='/login'>Try again</a>`,
    );
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
  res.send("Page not found - 404");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
