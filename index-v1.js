const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const crypto = require("crypto");
const base64url = require("base64url");
// const session = require("express-session");
// const cookieParser = require("cookie-parser");
require("dotenv").config();

const port = process.env.PORT || 3000;
const app = express();
const cors = require("cors");
const secretKey = crypto.randomBytes(64).toString("hex");

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// app.use(cookieParser());
// app.use(
//   session({
//     secret: secretKey,
//     resave: false,
//     saveUninitialized: true,
//   })
// );

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

// app.get("/logout", (req, res) => {
//   req.session.destroy((err) => {
//     if (err) {
//       console.error("Failed to destroy session during logout:", err);
//       res.status(500).send("Failed to logout");
//     } else {
//       // Clear all cookies
//       for (let cookie in req.cookies) {
//         res.clearCookie(cookie, { path: "/" });
//       }

//       // Redirect to client-side logout handler
//       res.redirect("/client-logout");
//     }
//   });
// });

// app.get("/client-logout", (req, res) => {
//   const shopifyLogoutUrl = `https://${process.env.SHOPIFY_STORE}/account/logout`;

//   res.send(`
//     <html>
//       <head>
//         <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
//         <meta http-equiv="Pragma" content="no-cache" />
//         <meta http-equiv="Expires" content="0" />
//       </head>
//       <body>
//         <script>
//           // Clear client-side cookies
//           document.cookie.split(';').forEach(cookie => {
//             const eqPos = cookie.indexOf('=');
//             const name = eqPos > -1 ? cookie.substring(0, eqPos) : cookie;
//             document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:00 GMT';
//           });

//           // Redirect to Azure B2C logout
//           window.location.href = '${shopifyLogoutUrl}';
//         </script>
//       </body>
//     </html>
//   `);
// });

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

        console.log(customerData);

        const multipassToken = generateToken(
          customerData,
          process.env.SHOPIFY_MULTIPASS_SECRET
        );

        // Verify and decrypt the token
        const decryptedData = verifyAndDecryptToken(
          multipassToken,
          process.env.SHOPIFY_MULTIPASS_SECRET
        );

        shopifyUrl = `https://${process.env.SHOPIFY_STORE}/account/login/multipass/${multipassToken}`;
        email = customerData.email;

        res.json({ shopifyUrl, email: customerData.email });
      }
    );
  } catch (error) {
    console.error("Error decoding token:", error);
    res.status(500).send("Authentication failed");
  }
});

function decrypt(encryptedData, encryptionKey) {
  const iv = encryptedData.subarray(0, 16);
  const encrypted = encryptedData.subarray(16);

  const decipher = crypto.createDecipheriv("aes-128-cbc", encryptionKey, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

function verifyAndDecryptToken(token, multipassSecret) {
  const { encryptionKey, signatureKey } = deriveKeys(multipassSecret);

  const decoded = base64url.toBuffer(token);
  const ciphertext = decoded.subarray(0, decoded.length - 32);
  const signature = decoded.subarray(decoded.length - 32);

  // Verify the signature
  const expectedSignature = sign(ciphertext, signatureKey);
  if (!crypto.timingSafeEqual(signature, expectedSignature)) {
    throw new Error("Invalid signature");
  }

  // Decrypt the ciphertext
  const decryptedData = decrypt(ciphertext, encryptionKey);
  return JSON.parse(decryptedData);
}

function deriveKeys(multipassSecret) {
  // Use the Multipass secret to derive two cryptographic keys,
  // one for encryption, one for signing
  const keyMaterial = crypto
    .createHash("sha256")
    .update(multipassSecret)
    .digest();
  const encryptionKey = keyMaterial.subarray(0, 16);
  const signatureKey = keyMaterial.subarray(16, 32);
  return { encryptionKey, signatureKey };
}

function generateToken(customerData, multipassSecret) {
  const { encryptionKey, signatureKey } = deriveKeys(multipassSecret);

  // Store the current time in ISO8601 format.
  // The token will only be valid for a small timeframe around this timestamp.
  customerData.created_at = new Date().toISOString();

  // Serialize the customer data to JSON and encrypt it
  const ciphertext = encrypt(JSON.stringify(customerData), encryptionKey);

  // Create a signature (message authentication code) of the ciphertext
  // and encode everything using URL-safe Base64 (RFC 4648)
  const token = base64url(
    Buffer.concat([ciphertext, sign(ciphertext, signatureKey)])
  );
  return token;
}

function encrypt(plaintext, encryptionKey) {
  // Use a random IV
  const iv = crypto.randomBytes(16);

  // Use IV as first block of ciphertext
  const cipher = crypto.createCipheriv("aes-128-cbc", encryptionKey, iv);
  const encrypted = Buffer.concat([
    iv,
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return encrypted;
}

function sign(data, signatureKey) {
  return crypto.createHmac("sha256", signatureKey).update(data).digest();
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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
