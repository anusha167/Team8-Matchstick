
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

// define server behavior
const app = express();
// parses incoming JSON data
app.use(express.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));
// parse URL-encoded data, allows for arrays
app.use(bodyParser.urlencoded({extended: true}));

// session middleware
app.use(session({
  // encrypt session ID cookie so cookie can't be tampered with
  secret: 'matchstick123',
  resave: false,
  saveUninitialized: true
}))
// connect to mySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'matchstick123',
  database: 'matchstick'
});

// looks for requests
app.listen(3000, () => {
  console.log('Server running on https://localhost:3000');
});

// throws error if MySQL fails to connect
db.connect(err => {
  if(err)
    throw err;
  console.log('Connect to MySQL');
});

app.get('/', (req, res) => 
{
  res.redirect('/login');
});

// serve register page (route)
app.get('/register', (req, res) => {
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
  // form sends data correctly
  console.log(req.body);

  // contains data submitted from form
  const{username, password} = req.body;
  // hides/hashes password from user view (bcrypt)
  const password_hash = await bcrypt.hash(password, 10);

  db.query(
    // if username already exists
    'SELECT * FROM users WHERE username = ?',
    [username],
    (err, rows) => 
    {
      if(err)
      {
        throw err;
      }
      if(rows.length > 0)
      {
        return res.redirect('/register?error=username_taken');
      }

      // otherwise insert new user
      db.query(
        // insert into users table created in MySQL database
        'INSERT INTO users (username, password_hash) VALUES (?, ?)',
        [username, password_hash],
        (err, result) => 
        {
          if(err)
          {
            throw err;
          }
          // redirect to login
          res.redirect('/login?registered=true');
        }
      );
    }
  );
});

// login to existing user
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // look for usernames
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if(err)
    {
      throw err;
    }
    // user isn't found
    if(results.length == 0)
    {
      return res.send('User not found');
    }

    const user = results[0];
    // compares password and looks for match
    bcrypt.compare(password, user.password_hash, (err, match) => {
      if(match) 
      {
        req.session.user = { id: user.id, username: user.username };
        // go to dashboard upon successful login
        res.redirect('/dashboard');
      }
      else
      {
        res.redirect('/login?password=false');
      }
    });
  });
});

