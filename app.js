const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = 3000;
const SECRET_KEY = "yonko";
const REFRESH_SECRET_KEY = "yonko_refresh";

// Correct CORS configuration
app.use(
  cors({
    origin: "http://localhost:8080",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.options("*", cors());

app.use(bodyParser.json());
app.use(express.json());

// Mock user database
const users = [
  {
    id: 1,
    username: "user1",
    email: "user1@example.com",
    password: "password1",
    role: "chef-equipe",
    name: "John Doe",
  },
  {
    id: 2,
    username: "user2",
    email: "user2@example.com",
    password: "password2",
    role: "manager",
    name: "Jane Smith",
  },
];

// Middleware to authenticate JWT
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.status(403).json({ message: "Invalid token" });
      req.user = user;
      next();
    });
  } else {
    console.log("Unauthorized");
    res.status(401).json({ message: "Unauthorized" });
  }
}

// Add refresh token storage (replace with a database in production)
let refreshTokens = [];

// Add refresh token endpoint
app.post("/token", (req, res) => {
  console.log("api/token");
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh Token Required" });
  }

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ message: "Invalid Refresh Token" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid Refresh Token" });

    const accessToken = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, {
      expiresIn: 60,
    });

    res.json({ accessToken });
  });
});

// Add logout endpoint
app.post("/logout", (req, res) => {
  console.log("api/logout");
  const { refreshToken } = req.body;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(204).end();
});

app.get("/user/me", authenticateJWT, (req, res) => {
  console.log("api/user/me");
  const user = users.find((u) => u.id === req.user.id);
  res.json({
    id: req.user.id,
    name: user.name,
    role: user.role,
    email: user.email,
  });
});

app.post("/login", (req, res) => {
  console.log("api/login");
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email && u.password === password);

  if (user) {
    const accessToken = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, {
      expiresIn: 60,
    });

    const refreshToken = jwt.sign(
      { id: user.id, role: user.role },
      REFRESH_SECRET_KEY,
      {
        // 10min
        expiresIn: 60 * 10,
      }
    );

    refreshTokens.push(refreshToken);

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        email: user.email,
      },
    });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// Add a new route for /users
app.get("/users", authenticateJWT, (req, res) => {
  res.json(
    users.map((user) => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      username: user.username,
    }))
  );
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
