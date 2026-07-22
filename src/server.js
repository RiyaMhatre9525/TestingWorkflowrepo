const express = require("express");
const { applySecurityHeaders, applyCorrelationContext } = require("./middleware/security");
const { findUserByEmail, createUser, logUserLogin, logUserLogout } = require("./db/models");

const app = express();

// Remove X-Powered-By header
app.disable("x-powered-by");

app.use(express.json());

applySecurityHeaders(app);
app.use(applyCorrelationContext);

app.post("/api/login", async (req, res) => {
  const { email } = req.body;
  const user = await findUserByEmail(email);
  logUserLogin(email, !!user, req.correlation_id);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.json({ message: "Login successful" });
});

app.post("/api/register", async (req, res) => {
  const { email, passwordHash } = req.body;
  const user = await createUser(email, passwordHash, req.correlation_id);
  res.status(201).json(user);
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});