const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = 3000;
const SECRET_KEY = "yonko";
const REFRESH_SECRET_KEY = "yonko_refresh";

app.use(
  cors({
    origin: "http://localhost:8080",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

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

let refreshTokens = [];

app.post("/token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh Token Required" });
  }

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(401).json({ message: "Invalid Refresh Token" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
    if (err) return res.status(401).json({ message: "Invalid Refresh Token" });

    const accessToken = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, {
      expiresIn: 20,
    });

    res.json({ accessToken });
  });
});

function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.status(401).json({ message: "Invalid token" });
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
}

app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(204).end();
});

app.get("/user/me", authenticateJWT, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  res.json({
    id: req.user.id,
    name: user.name,
    role: user.role,
    email: user.email,
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email && u.password === password);

  if (user) {
    const accessToken = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, {
      expiresIn: 20,
    });

    const refreshToken = jwt.sign(
      { id: user.id, role: user.role },
      REFRESH_SECRET_KEY,
      {
        expiresIn: 60,
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
