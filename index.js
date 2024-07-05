// const express = require("express");
// const axios = require("axios");
// const jwt = require("jsonwebtoken");
// const jwksClient = require("jwks-rsa");
// const crypto = require("crypto");
// require("dotenv").config();

// const app = express();
// const cors = require("cors");
// app.use(cors({ origin: "*" }));

// const port = process.env.PORT || 3000;

// const client = jwksClient({
//   jwksUri: `https://keeprdev.b2clogin.com/${process.env.B2C_TENANT}/discovery/v2.0/keys?p=${process.env.B2C_POLICY}`,
// });

// function getPublicKey(kid) {
//   return new Promise((resolve, reject) => {
//     client.getSigningKey(kid, (err, key) => {
//       if (err) {
//         return reject(err);
//       }
//       resolve(key.getPublicKey());
//     });
//   });
// }

// app.get("/auth", (req, res) => {
//   // https://keeprdev.b2clogin.com/keeprdev.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_SignUpSignIn&client_id=70b068d7-9160-4a7f-b8fd-e65d93c9da5b&nonce=defaultNonce&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&scope=openid&response_type=id_token&prompt=login
//   // const redirectUri = `https://keeprdev.b2clogin.com/${process.env.B2C_TENANT}/oauth2/v2.0/authorize?p=${process.env.B2C_POLICY}&client_id=${process.env.B2C_CLIENT_ID}&nonce=defaultNonce&redirect_uri=${process.env.REDIRECT_URI}&scope=openid&response_type=id_token&prompt=login`;
//   const redirectUri = `https://keeprdev.b2clogin.com/keeprdev.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_SignUpSignIn&client_id=70b068d7-9160-4a7f-b8fd-e65d93c9da5b&nonce=defaultNonce&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&scope=openid&response_type=id_token&prompt=login`;
//   res.redirect(redirectUri);
// });

// app.get("/auth/callback", async (req, res) => {
//   const idToken = req.query.id_token;

//   if (!idToken) {
//     return res.status(400).send("ID token not provided");
//   }

//   try {
//     const decodedToken = jwt.decode(idToken, { complete: true });
//     if (!decodedToken) {
//       throw new Error("Invalid token");
//     }

//     const publicKey = await getPublicKey(decodedToken.header.kid);

//     jwt.verify(
//       idToken,
//       publicKey,
//       { algorithms: ["RS256"] },
//       async (err, decoded) => {
//         if (err) {
//           console.error("Token verification failed:", err);
//           return res.status(401).send("Token verification failed");
//         }

//         // Use decoded information to create a session and authenticate the user with Shopify
//         const email = decoded.email;
//         const multipassToken = createMultipassToken({ email });

//         const shopifyUrl = `https://${process.env.SHOPIFY_STORE}/account/login/multipass/${multipassToken}`;
//         res.redirect(shopifyUrl);
//       }
//     );
//   } catch (error) {
//     console.error("Error decoding token:", error);
//     res.status(500).send("Authentication failed");
//   }
// });

// function createMultipassToken(customerData) {
//   const key = Buffer.from(process.env.SHOPIFY_MULTIPASS_SECRET, "utf8");
//   const iv = crypto.randomBytes(16);
//   const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
//   let encrypted = cipher.update(JSON.stringify(customerData), "utf8", "base64");
//   encrypted += cipher.final("base64");
//   const multipassToken = Buffer.concat([
//     iv,
//     Buffer.from(encrypted, "base64"),
//   ]).toString("base64");
//   return multipassToken;
// }

// app.listen(port, () => {
//   console.log(`Server running at http://localhost:${port}`);
// });

const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const crypto = require("crypto");
require("dotenv").config();

const port = process.env.PORT || 3000;
const app = express();
const cors = require("cors");

app.use(cors({ origin: "*" }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const client = jwksClient({
  jwksUri: `https://keeprdev.b2clogin.com/${process.env.B2C_TENANT}/discovery/v2.0/keys?p=${process.env.B2C_POLICY}`,
});

function getPublicKey(kid) {
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (err, key) => {
      if (err) {
        return reject(err);
      }
      resolve(key.getPublicKey());
    });
  });
}

app.get("/auth", (req, res) => {
  const redirectUri = `https://keeprdev.b2clogin.com/${process.env.B2C_TENANT}/oauth2/v2.0/authorize?p=${process.env.B2C_POLICY}&client_id=${process.env.B2C_CLIENT_ID}&nonce=defaultNonce&response_type=id_token&redirect_uri=${process.env.REDIRECT_URI}&scope=openid&prompt=login`;
  res.redirect(redirectUri);
});

app.get("/auth/callback", (req, res) => {
  res.send(`
    <html>
      <head>
        <script>
          (function() {
            const fragment = window.location.hash.substring(1);
            const params = new URLSearchParams(fragment);
            const idToken = params.get("id_token");
            if (idToken) {
              fetch('/auth/callback/token', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({ id_token: idToken })
              }).then(response => {
                if (response.ok) {
                  window.location.href = '/auth/success';
                } else {
                  window.location.href = '/auth/failure';
                }
              });
            } else {
              window.location.href = '/auth/failure';
            }
          })();
        </script>
      </head>
      <body>
      </body>
    </html>
  `);
});

app.post("/auth/callback/token", async (req, res) => {
  const { id_token } = req.body;

  if (!id_token) {
    return res.status(400).send("ID token not provided");
  }

  try {
    const decodedToken = jwt.decode(id_token, { complete: true });
    if (!decodedToken) {
      console.error("Invalid token");
      return;
    }

    const publicKey = await getPublicKey(decodedToken.header.kid);

    jwt.verify(
      id_token,
      publicKey,
      { algorithms: ["RS256"] },
      async (err, decoded) => {
        if (err) {
          console.error("Token verification failed:", err);
          return res.status(401).send("Token verification failed");
        }

        const { emails, given_name, family_name } = decoded;
        const customerData = {
          email: emails[0],
          first_name: given_name,
          last_name: family_name,
        };

        const multipassToken = createMultipassToken(customerData);

        const shopifyUrl = `https://${process.env.SHOPIFY_STORE}/account/login/multipass/${multipassToken}`;
        res.redirect(shopifyUrl);
      }
    );
  } catch (error) {
    console.error("Error decoding token:", error);
    res.status(500).send("Authentication failed");
  }
});

function createMultipassToken(customerData) {
  const key = Buffer.from(process.env.SHOPIFY_MULTIPASS_SECRET, "utf8");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(JSON.stringify(customerData), "utf8", "base64");
  encrypted += cipher.final("base64");
  const multipassToken = Buffer.concat([
    iv,
    Buffer.from(encrypted, "base64"),
  ]).toString("base64");
  return multipassToken;
}

app.get("/auth/success", (req, res) => {
  res.send("Authentication successful! You will be redirected shortly.");
});

app.get("/auth/failure", (req, res) => {
  res.send("Authentication failed! Please try again.");
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
