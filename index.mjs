import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { PORT, JWT_SECRET } from "./config.mjs";
import { UserRepository } from "./user-repository.mjs";

const app = express();

// Set the view engine to ejs
app.set("view engine", "ejs");

app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
  const token = req.cookies.access_token;
  req.session = { user: null };

  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.session.user = data;
  } catch (error) {}

  next();
});

app.get("/", (req, res) => {
  const { user } = req.session;
  if (user) {
    res.render("index", { username: user.username });
  } else {
    res.render("index", { username: null });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await UserRepository.login({ username, password });
    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" },
    );
    res
      .cookie("access_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 1000 * 60 * 60,
      })
      .send({ user });
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const id = await UserRepository.create({ username, password });
    res.status(201).send({ id });
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

app.post("/logout", async (req, res) => {
  res.clearCookie("access_token").send({ message: "Logged out" });
});

app.get("/protected", async (req, res) => {
  const { user } = req.session;

  if (!user) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  res.render("protected", { username: user.username });
});

app.listen(PORT, () => {
  log(`Server is running on port ${PORT}`, "cyan");
  log("This is a yellow message", "yellow");
  log("This is a red message", "red");
  log("This is a green message", "green");
});

function log(m, color) {
  switch (color) {
    case "yellow":
      console.log("\x1b[33m%s\x1b[0m", m);
      break;
    case "red":
      console.log("\x1b[31m%s\x1b[0m", m);
      break;
    case "green":
      console.log("\x1b[32m%s\x1b[0m", m);
      break;
    case "blue":
      console.log("\x1b[34m%s\x1b[0m", m);
      break;
    case "purple":
      console.log("\x1b[34m%s\x1b[0m", m);
      break;
    case "cyan":
      console.log("\x1b[36m%s\x1b[0m", m);
      break;
    default:
      console.log("\x1b[37m%s\x1b[0m", m);
      break;
  }
}
/**
 * @TODO:
 * - Implement FORBIDDEN authorization for protected route with user role
 */
