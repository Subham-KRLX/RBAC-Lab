const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Secret key for JWT signing
const JWT_SECRET = "newtonschoolsecret";

// In-memory user data
const users = [
  { username: "yash", password: "123", role: "admin" },
  { username: "ankit", password: "123", role: "teacher" },
  { username: "anurag", password: "123", role: "student" },
];

// --- LOGIN ROUTE ---
app.post("/login", (req, res) => {
  const { username, password } = req.body
  const user = users.find(u => u.username === username && u.password === password)

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }
  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "1h" })
  res.json({ token })
});

// --- AUTH MIDDLEWARE ---
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization
  
  // Check for missing token or incorrect format ("Bearer <token>")
  if (!authHeader || !authHeader.startsWith("Bearer ")) { // Added space after Bearer
    return res.status(401).json({ message: "Missing token" })
  }
  
  // Extract token string
  const token = authHeader.split(' ')[1]

  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Attach decoded user payload to request for use in 'authorize'
    req.user = decoded 
    
    // Token is valid, continue
    next(); 
  } catch (err) {
    // 403: Invalid token (expired, wrong signature, etc.)
    return res.status(403).json({ message: "Invalid token" })
  }
};

// --- ROLE CHECK MIDDLEWARE ---
const authorize = (allowedRoles) => (req, res, next) => {
  if (req.user && allowedRoles.includes(req.user.role)) {
    next();
  } else {
    return res.status(403).json({ message: "Access denied" });
  }
};

// --- PROTECTED ROUTES ---
app.get("/admin", authenticate, authorize(["admin"]), (req, res) => {
  res.send("Welcome, admin!");
});

app.get("/teacher", authenticate, authorize(["teacher"]), (req, res) => {
  res.send("Welcome, teacher!");
});

app.get("/student", authenticate, authorize(["student"]), (req, res) => {
  res.send("Welcome, student!");
});

app.get("/test", (req, res) => {
  res.send("hi");
});

module.exports = app;

// --- RUN DIRECTLY IF NOT TESTING -
// --
const PORT = 3300;
app.listen(PORT, () => console.log(`Server running on port http://localhost:${PORT}`));
