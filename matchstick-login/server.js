
// PURPOSE: this file tells Node.js to look for and manage requests, connects to database in MySQL, and secures data

// sets up Express.js (server-side web framework)
const express = require('express');
// sets up MySQL (database system)
const mysql = require('mysql2');
// sets up bcrypt (for security)
const bcrypt = require('bcrypt');
// parses json data from html requests
const bodyParser = require('body-parser')

// define server behavior
const app = express();
// parses incoming JSON data
app.use(express.json());
// parse URL-encoded data, allows for arrays
app.use(bodyParser.urlencoded({extended: true}));

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

// handle form submission (MAKE SURE TO ADD TO <FORM> AS ACTION TYPE)
app.post('/register', async (req, res) => {
  // form sends data correctly
  console.log(req.body);

  const{username, password} = req.body;
  // hides/hashes password from user view (bcrypt)
  const password_hash = await bcrypt.hash(password, 10);

  db.query(
    // insert into users table created in MySQL database
    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
    [username, password_hash],
    (err, result) => {
      if(err)
        throw err;
      res.send('User registered');
    }
  );
});