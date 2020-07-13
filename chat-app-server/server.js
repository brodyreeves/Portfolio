// server.js
// where your node app starts

// init project
const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const fs = require("fs");
const crypto = require("crypto");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// http://expressjs.com/en/starter/static-files.html
app.use(express.static("public"));

// init sqlite db
const dbFile = "./.data/lxrnDB.db";
const exists = fs.existsSync(dbFile);
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(dbFile);

///////////////////////////
//  INITIALIZE DATABASE  //
///////////////////////////

// if ./.data/lxrnDB.db does not exist, create it
db.serialize(() => {
  if (!exists) {
    // Create tables, log errors if any occur
    db.run("CREATE TABLE Users (id INTEGER PRIMARY KEY AUTOINCREMENT, uname TEXT NOT NULL UNIQUE, pw TEXT NOT NULL, key TEXT NOT NULL)", error => { if (error) { console.log("User table failed", error.message); } else { console.log("User table created"); }});

    db.run("CREATE TABLE Auth (id INTEGER PRIMARY KEY AUTOINCREMENT, uname TEXT NOT NULL UNIQUE, auth_token TEXT NOT NULL, expires TEXT DEFAULT (datetime('now', '+1 hour')) NOT NULL CHECK(expires > datetime('now')))", error => { if (error) { console.log("Auth table failed", error.message); } else { console.log("Auth table created"); }});

    db.run("CREATE TABLE Drops (id INTEGER PRIMARY KEY AUTOINCREMENT, src TEXT NOT NULL, dest TEXT NOT NULL, msg TEXT NOT NULL, sent TEXT DEFAULT (datetime('now')) NOT NULL, expires TEXT DEFAULT (datetime('now', '+1 month')) NOT NULL CHECK(expires > datetime('now')))", error => { if (error) { console.log("Drops table failed", error.message); } else { console.log("Drops table created"); }});

    // DEBUGGING INITIALIZE DATABASE WITH SOME VALUES
//     db.run("INSERT INTO Users (uname, pw) VALUES (?, ?)", 'TestName', encrypt('testpw'), error => { if (error) { console.log("Debug1 failed", error.message); } else { console.log("Debug1 entered"); }});

//     db.run("INSERT INTO Users (uname, pw) VALUES (?, ?)", 'TestName2', encrypt('wptset'), error => { if (error) { console.log("Debug2 failed", error.message); } else { console.log("Debug2 entered"); }});

//     db.run("INSERT INTO Auth (uname, auth_token) VALUES (?, ?)", 'TestName', crypto.randomBytes(20).toString('hex'), error => { if (error) { console.log("Debug3 failed", error.message); } else { console.log("Debug3 entered"); }});

//     db.run("INSERT INTO Drops (src, dest, msg) VALUES (?, ?, ?)", 'TestName', 'TestName2', encrypt('test message here'), error => { if (error) { console.log("Debug4 failed", error.message); } else { console.log("Debug4 entered"); }});

  } else {
    console.log("Database ready to go!");
  }
});

///////////////////////
//  ENCRYPTION KEYS  //
///////////////////////

// https://nodejs.org/api/crypto.html#crypto_crypto_generatekeypair_type_options_callback
// synchronous call to get values when expected
const keyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: process.env.CRYPTO_CIPHER_KEY,
  }
}, (err, publicKey, privateKey) => {
  // Handle errors and use the generated key pair.
  if (err) {
    console.log("Key generation error:", err.message)
  }
});

/////////////////
//  ENDPOINTS  //
/////////////////

app.post("/v1/register", (req, res) => {
  // call to register a new account
  // req.body.username req.body.password, req.body.publickey

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/register': ", req.body);

  const cliUser = req.body.username;
  const cliPw = req.body.password;
  const cliKey = req.body.publickey;

  if (!cliUser || !cliPw || !cliKey) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  // always store passwords as encrypted strings
  let sql = "INSERT INTO Users (uname, pw, key) VALUES (?, ?, ?)";
  db.run(sql, cliUser, encrypt(cliPw), cliKey, err => {
    if (err) {
      res.status(401).json({ error: 'username taken' });
      console.log("Respond 401 due to taken username |", err.message);
      return;

    } else {
      let token = crypto.randomBytes(20).toString('hex');
      console.log("User registered; generated token:", token);

      let sql = "INSERT INTO Auth (uname, auth_token) VALUES (?, ?)";
      db.run(sql, cliUser, token, error => {
        if (error) {
          res.status(500).json({ error: 'server error' });
          console.log("Respond 500 due to INSERT error:", error.message);
          return;

        } else {
          res.status(200).json({ auth_token: token });
          console.log("Respond 200 with token:", token);
          return;
        }
      });
    }
  })
});

app.post("/v1/login", (req, res) => {
  // call to log into an account
  // req.body.username req.body.password

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/login': ", req.body);

  const cliUser = req.body.username;
  const cliPw = req.body.password;

  if (!cliUser || !cliPw) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  let sql = "SELECT uname, pw FROM Users WHERE uname  = ?";
  db.get(sql, [cliUser], (err, row) => {
    if (err) {
      res.status(500).json({ error: 'server error' });
      console.log("Respond 500 due to SELECT error:", err.message);
      return;

    } else {
      if (row) {
        console.log("Found a match for username", cliUser, "in row", row);

        // check if passwords match
        if (decrypt(row.pw) === cliPw) {
          let token = crypto.randomBytes(20).toString('hex');
          console.log("Passwords match; generated token:", token);

          // can only have one entry per username, insert if no current entry or replace existing
          // give token one hour for a valid login (before users must relog)
          let sql = "REPLACE INTO Auth (uname, auth_token) VALUES (?, ?)";
          db.run(sql, cliUser, token, error => {
            if (error) {
              res.status(500).json({ error: 'server error' });
              console.log("Respond 500 due to INSERT error:", error.message);
              return;

            } else {
              res.status(200).json({ auth_token: token });
              console.log("Respond 200 with token:", token);
              return;
            }
          });

        } else {
          res.status(401).json({ error: 'username/password mismatch' });
          console.log("Respond 401 due to bad password");
          return;
        }

      } else {
        res.status(401).json({ error: 'username/password mismatch' });
        console.log("Respond 401 due to bad username");
      }
    }
  });
});

app.post("/v1/send", (req, res) => {
  // call to send a message
  // req.body.auth_token, , req.body.dest, req.body.msg, (optional)req.body.expires

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/send': ", req.body);

  let cliToken = req.body.auth_token;
  let cliDest = req.body.dest;
  let cliMsg = encrypt(req.body.msg); // store messages as encrypted strings
  let cliExp = req.body.expires;

  if (!cliToken || !cliDest || !cliMsg) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  // check authentication
  let sql = "SELECT uname FROM Auth WHERE auth_token  = ? AND expires > datetime('now')";
  db.get(sql, [cliToken], (err, row) => {
    if (err) {
      res.status(500).json({ error: 'server error' });
      console.log("Respond 500 due to SELECT error:", err.message);
      return;

    } else {
      if (row) {
        let cliUser = row.uname;
        console.log("User has been authenticated:", cliUser);

        // check destination
        let sql = "SELECT uname FROM Users WHERE uname = ?";
        db.get(sql, [cliDest], (error, row) => {
          if (error) {
            res.status(500).json({ error: 'server error' });
            console.log("Respond 500 due to SELECT error:", error.message);
            return;

          } else {
            if (row) {
              if (cliExp) { // use the provided expiration
                console.log("using cliExp", cliExp);

                if (isValidDate(cliExp)) {
                  let sql = "INSERT INTO Drops (src, dest, msg, expires) VALUES (?, ?, ?, ?)";
                  db.run(sql, cliUser, cliDest, cliMsg, cliExp, error => {
                    if (error) {
                      res.status(500).json({ error: 'server error' });
                      console.log("Respond 500 due to INSERT error:", error.message);
                      return;

                    } else {
                      res.status(200).json({ confirmation: 'message dropped' });
                      console.log("Respond 200 with confirmation of drop");
                      return;
                    }
                  });

                } else {
                  res.status(400).json({ error: 'invalid expires' });
                  console.log("Respond 400 due to bad expires");
                  return;
                }

              } else { // use default expiration
                let sql = "INSERT INTO Drops (src, dest, msg) VALUES (?, ?, ?)";
                db.run(sql, cliUser, cliDest, cliMsg, error => {
                  if (error) {
                    res.status(500).json({ error: 'server error' });
                    console.log("Respond 500 due to INSERT error:", error.message);
                    return;

                  } else {
                    res.status(200).json({ confirmation: 'message dropped' });
                    console.log("Respond 200 with confirmation of drop");
                    return;
                  }
                });
              }

            } else {
              res.status(400).json({ error: 'bad destination' });
              console.log("Respond 400 due to bad destination");
              return;
            }
          }
        });

      } else {
        res.status(401).json({ error: 'bad auth_token' });
        console.log("Respond 401 due to bad auth_token");
      }
    }
  });
});

app.get("/v1/receive", (req, res) => {
  // call to receive messages for user with auth_token in field
  // req.body.auth_token

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/receive': ", req.body);

  let cliToken = req.body.auth_token;

  if (!cliToken) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  // check authentication
  let sql = "SELECT uname FROM Auth WHERE auth_token  = ? AND expires > datetime('now')";
  db.get(sql, [cliToken], (err, row) => {
    if (err) {
      res.status(500).json({ error: 'server error' });
      console.log("Respond 500 due to SELECT error:", err.message);
      return;

    } else {
      if (row) {
        let cliUser = row.uname;
        console.log("User has been authenticated:", cliUser);

        // retrieve messages
        let sql = "SELECT src, msg, sent FROM Drops WHERE dest = ? AND expires > datetime('now')";
        db.all(sql, [cliUser], (error, rows) => {
          if (error) {
            res.status(500).json({ error: 'server error' });
            console.log("Respond 500 due to SELECT error:", error.message);
            return;

          } else {
            if (rows) {
              // decrypt messages before responding
              rows.forEach(row => {
                row.msg = decrypt(row.msg);
              });

              res.status(200).json({ messages: rows });
              console.log("Respond 200 with messages", rows);
              return;

            } else {
              res.status(200).json({ messages: 'none' });
              console.log("Respond 200 no messages");
              return;
            }
          }
        });

      } else {
        res.status(401).json({ error: 'bad auth_token' });
        console.log("Respond 401 due to bad auth_token");
      }
    }
  });
});

app.post("/v1/delete", (req, res) => {
  // call to delete messages
  // req.body.auth_token, req.body.src, req.body.dest, req.body.sent

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/delete': ", req.body);

  let cliToken = req.body.auth_token;
  let cliSrc = req.body.src;
  let cliDest = req.body.dest;
  let cliSent = req.body.sent;

  if (!cliToken || !cliSrc || !cliDest || !cliSent) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  // check authentication
  let sql = "SELECT uname FROM Auth WHERE auth_token  = ? AND expires > datetime('now') AND uname = ?";
  db.get(sql, [cliToken, cliDest], (err, row) => {
    if (err) {
      res.status(500).json({ error: 'server error' });
      console.log("Respond 500 due to SELECT error:", err.message);
      return;

    } else {
      if (row) {
        console.log("User has been authenticated:", row.uname);

        // delete messages
        let sql = "DELETE FROM Drops WHERE src = ? AND dest = ? AND sent = ?";
        db.run(sql, cliSrc, cliDest, cliSent, error => {
          if (error) {
            res.status(500).json({ error: 'server error' });
            console.log("Respond 500 due to DELETE error:", err.message);
            return;

          } else {
            res.status(200).json({ confirmation: 'messages deleted' });
            console.log("Respond 200 with confirmation of deletion");
            return;
          }
        });

      } else {
        res.status(401).json({ error: 'bad auth_token' });
        console.log("Respond 401 due to bad auth_token");
      }
    }
  });
});

app.post("/v1/logout", (req, res) => {
  // call to log out a user
  // req.body.auth_token, req.body.username

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/logout': ", req.body);

  let cliToken = req.body.auth_token;
  let cliUser = req.body.username;

  if (!cliToken || !cliUser) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  // check authentication
  let sql = "SELECT uname FROM Auth WHERE auth_token  = ? AND expires > datetime('now') AND uname = ?";
  db.get(sql, [cliToken, cliUser], (err, row) => {
    if (err) {
      res.status(500).json({ error: 'server error' });
      console.log("Respond 500 due to SELECT error:", err.message);
      return;

    } else {
      if (row) {
        console.log("User has been authenticated:", row.uname);

        let sql = "DELETE FROM Auth WHERE auth_token = ? AND uname = ?";
        db.run(sql, cliToken, cliUser, error => {
          if (error) {
            res.status(500).json({ error: 'server error' });
            console.log("Respond 500 due to DELETE error:", err.message);
            return;

          } else {
            res.status(200).json({ confirmation: 'logged out' });
            console.log("Respond 200 with confirmation of log out");
            return;
          }
        });

      } else {
        res.status(401).json({ error: 'bad auth_token' });
        console.log("Respond 401 due to bad auth_token");
      }
    }
  });
});

app.get("/v1/fetchkey", (req, res) => {
  // call to retrieve public key

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/fetchkey': ", req.body);

  res.status(200).json( {publicKey: keyPair.publicKey });
  console.log("Respond 200 with key attached");
  return;
});

app.get("/v1/getUserKey", (req, res) => {
  // call to retrieve public key
  // req.body.auth_token, req.body.username, req.body.dest

  req.body = JSON.parse(privateDecrypt(req.body)); // server would call this on the incoming request.body
  console.log("Received request to '/v1/getUserKey': ", req.body);

  let cliToken = req.body.auth_token;
  let cliUser = req.body.username;
  let cliDest = req.body.dest;

  if (!cliToken || !cliUser || !cliDest) {
    res.status(400).json({ error: 'missing parameters' });
    console.log("Respond 401 due to missing parameters");
    return;
  }

  // check authentication
  let sql = "SELECT uname FROM Auth WHERE auth_token  = ? AND expires > datetime('now') AND uname = ?";
  db.get(sql, [cliToken, cliUser], (err, row) => {
    if (err) {
      res.status(500).json({ error: 'server error' });
      console.log("Respond 500 due to SELECT error:", err.message);
      return;

    } else {
      if (row) {
        console.log("User has been authenticated:", row.uname);

        let sql = "SELECT key FROM Users WHERE uname = ?";
        db.get(sql, cliDest, (error, row) => {
          console.log("row:", row);
          if (error) {
            res.status(500).json({ error: 'server error' });
            console.log("Respond 500 due to SELECT error:", error.message);
            return;

          } else {
            res.status(200).json({ key: row.key });
            console.log("Respond 200 with public key for user:", cliDest, row.key);
            return;
          }
        });

      } else {
        res.status(401).json({ error: 'bad auth_token' });
        console.log("Respond 401 due to bad auth_token");
      }
    }
  });
});

/////////////////
//  FUNCTIONS  //
/////////////////

function encrypt(text) { // example of crypto https://stackoverflow.com/a/60370205
  let iv = crypto.randomBytes(16);
  let cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(process.env.CRYPTO_CIPHER_KEY, 'hex'), iv);
  let ctext = cipher.update(text);
  ctext = Buffer.concat([ctext, cipher.final()]);
  return iv.toString('hex') + ':' + ctext.toString('hex');
}

function decrypt(text) { // example of crypto https://stackoverflow.com/a/60370205
  let textParts = text.split(':');
  let iv = Buffer.from(textParts.shift(), 'hex');
  let ctext = Buffer.from(textParts.join(':'), 'hex');
  let decipher = crypto.createDecipheriv('aes-256-ctr', Buffer.from(process.env.CRYPTO_CIPHER_KEY, 'hex'), iv);
  let ptext = decipher.update(ctext);
  ptext = Buffer.concat([ptext, decipher.final()]);
  return ptext.toString();
}

// https://stackoverflow.com/questions/8750780/encrypting-data-with-public-key-in-node-js/53650554#53650554

// let plainObject = { a: 'a', b: 'b' }; // i.e. response.body content
// let encryptedString = publicEncrypt(JSON.stringify(plain)); // client would call this
// let decryptedObject = JSON.parse(privateDecrypt(enc)); // server would call this on the incoming request.body

function publicEncrypt(text) {
  const buffer = Buffer.from(text, 'utf8');
  const ctext = crypto.publicEncrypt(keyPair.publicKey, buffer);
  return ctext.toString('base64');
}

function privateDecrypt(text) {
  const buffer = Buffer.from(text, 'base64');
  const ptext = crypto.privateDecrypt(
    {
      key: keyPair.privateKey,
      passphrase: process.env.CRYPTO_CIPHER_KEY,
    },
    buffer,
  );
  return ptext.toString('utf8')
}

// Validates that the input string is a valid date formatted as YYYY-MM-DD HH:MM:SS
// adapted from https://stackoverflow.com/questions/6177975/how-to-validate-date-with-format-mm-dd-yyyy-in-javascript
function isValidDate(dateString) {
  // First check for the pattern
  if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(dateString)) return false;

  // Parse the date parts to integers
  var parts = dateString.split(" ");

  var dateParts = parts[0].split("-");
  var year = parseInt(dateParts[0], 10);
  var month = parseInt(dateParts[1], 10);
  var day = parseInt(dateParts[2], 10);

  var timeParts = parts[1].split(":");
  var hour = parseInt(timeParts[0], 10);
  var minute = parseInt(timeParts[1], 10);
  var second = parseInt(timeParts[2], 10);

  // Check the ranges of month and year
  if (year < 1000 || year > 3000 || month == 0 || month > 12) return false;

  var monthLength = [ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 ];

  // Adjust for leap years
  if (year % 400 == 0 || (year % 100 != 0 && year % 4 == 0)) monthLength[1] = 29;

  // Check the range of the day
  if (!(day > 0 && day <= monthLength[month - 1])) return false;

  // Check the hour
  if (!(hour >= 0 && hour < 24)) return false;

  // Check the minute
  if (!(minute >= 0 && minute < 60)) return false;

  // Check the second
  if (!(second >= 0 && second < 60)) return false;

  return true;
};

////////////////////////////////////////////////////////////////////////////////////////

// listen for requests
var listener = app.listen(process.env.PORT, () => {
  console.log(`Your app is listening on port ${listener.address().port}`);
});
