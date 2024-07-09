const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const crypto = require("crypto");
require("dotenv").config();

const port = process.env.PORT || 3000;
const app = express();
const cors = require("cors");

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
let shopifyUrl;
let email;

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

        shopifyUrl = `https://${process.env.SHOPIFY_STORE}/account/login/multipass/${multipassToken}`;
        email = customerData.email;
        console.log(shopifyUrl);
        // res.redirect(shopifyUrl);
        // res.send(`
        //   <html>
        //     <head></head>
        //     <body>
        //       Redirecting to Shopify...
        //       <a href="${shopifyUrl}">Shopify</a>
        //     </body>
        //   </html>
        // `);
        res.json({ shopifyUrl, email: customerData.email });
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
  res.send(`
    <html>
    <head>
      <title>Redirecting...</title>
    </head>
    <body>
      <script>
        (function() {
          fetch('/get-shopify-url').then(response => response.json()).then(data => {
              if (data.shopifyUrl && data.email) {
                // Redirect to Shopify URL
                window.location.href = data.shopifyUrl;
                // Call the check_login endpoint with the email
                fetch('/shopify/check_login?email=' + encodeURIComponent(data.email)).then(response => response.json()).then(loginData => {
                    console.log('Customer Data:', loginData);
                }).catch(error => {
                    console.error('Error checking login:', error);
                });
              } else {
                document.body.innerHTML = 'Error: No Shopify URL found';
              }
          });
        })();
      </script>
    </body>
    </html>
  `);
});

app.get("/auth/failure", (req, res) => {
  res.send("Authentication failed! Please try again.");
});

app.get("/get-shopify-url", (req, res) => {
  // This endpoint should return the Shopify URL after the user is authenticated
  res.json({ shopifyUrl, email });
});

app.get("/shopify/check_login", async (req, res) => {
  try {
    const shopifyUrl = `https://${process.env.SHOPIFY_STORE}/admin/customers/search.json?query=email:${req.query.email}`;
    console.log(`Shopify URL: ${shopifyUrl}`);

    const authHeader = `Basic ${Buffer.from(
      `${process.env.SHOPIFY_API_KEY}:${process.env.SHOPIFY_API_PASSWORD}`
    ).toString("base64")}`;

    console.log(`Auth Header: ${authHeader}`);

    const response = await axios.get(shopifyUrl, {
      headers: {
        Authorization: authHeader,
      },
    });

    console.log(`Shopify response status: ${response.status}`);
    console.log(`Shopify response data: ${JSON.stringify(response.data)}`);

    if (response.data.customers && response.data.customers.length > 0) {
      res.json({ customer: response.data.customers[0] });
    } else {
      res.status(404).send("Customer not found");
    }
  } catch (error) {
    console.error("Error fetching customer data:", error);
    res.status(500).send("Error fetching customer data");
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
