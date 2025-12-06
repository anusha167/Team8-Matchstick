
// PURPOSE: this file tells Node.js to look for and manage requests, connects to database in MySQL, and secures data
// NOTES FOR TEAMMATES: This is probably where all the backend will be, so please be very careful in what you remove/add

// sets up Express.js (server-side web framework)
const express = require('express');
// sets up MySQL (database system)
const mysql = require('mysql2');
// sets up bcrypt (for security)
const bcrypt = require('bcrypt');
// parses json data from html requests
const bodyParser = require('body-parser');
// sets up session management
const session = require('express-session');
// persistent session store in MySQL
const MySQLStore = require('express-mysql-session')(session);

// define server behavior
const app = express();
// parses incoming JSON data
app.use(express.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));
// parse URL-encoded data, allows for arrays
app.use(bodyParser.urlencoded({extended: true}));

// connection pool so you don't need to keep noding server.js
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'matchstick123',
  database: 'matchstick',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}).promise();

// session store backed by MySQL
const sessionStore = new MySQLStore({}, pool);

// session middleware
app.use(session({
    // encrypt session ID cookie so cookie can't be tampered with
    secret: 'matchstick123',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      secure: false,
      // max one hour session
      maxAge: 1000*60*60
  }
}));

// looks for requests
app.listen(3000, () => 
{
  console.log('Server running on http://localhost:3000');
});


app.get('/', (req, res) => 
{
  res.redirect('/login');
});

// serve register page (route)
app.get('/register', (req, res) => {
  // could use ejs but I don't want to keep downloading stuff
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// serve login page (route)
app.get('/login', (req, res) =>
{
  // joins these two paths
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
});

// serves dashboard page (route)
app.get('/dashboard', (req, res) =>
{
  // redirects to login page if not logged in
  if(!req.session.user)
  {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// serves logout (route)
app.get('/logout', (req, res) => 
{
  req.session.destroy(err => {
    if(err)
    {
      throw err;
    }
    res.redirect('/login');
  });
});

// handle form submission (MAKE SURE TO ADD TO <FORM> AS ACTION TYPE)
app.post('/register', async (req, res) => {
  // contains data submitted from form
  const{username, password} = req.body;
  // hides/hashes password from user view (bcrypt)
  const password_hash = await bcrypt.hash(password, 10);

  try
  {
    // runs a SQL query against MySQL databse using connection pool
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    // checks to see if row/user already exists
    if(rows.length > 0)
    {
      return res.redirect('/register?error=username_taken');
    }
    // inserts into database
    await pool.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, password_hash]);
    // redirect to login
    res.redirect('/login?registered=true');
  } 
  catch(err)
  {
    console.error(err);
    res.status(500).send('Error registering user');
  }
});

// login to existing user
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try
  {
    // runs a SQL query against MySQL database using connection pool
    const [results] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    // user is not found
    if(results.length == 0)
    {
      return res.redirect('/login?error=user_not_found');
    }
    const user = results[0];
    // checks to see if password is correct
    const match = await bcrypt.compare(password, user.password_hash);

    if(match)
    {
      // redirect to dashboard
      req.session.user = { id: user.id, username: user.username };
      res.redirect('/dashboard');
    }
    else
    {
      // redirect back to login with error
      return res.redirect('/login?error=invalid_password');
    }
  } 
  catch(err)
  {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/dashboard');
    }
    res.clearCookie('connect.sid'); // clear session cookie
    res.redirect('/login');         // send back to login page
  });
});

