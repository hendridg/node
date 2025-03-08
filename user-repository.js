import DBLocal from "db-local";
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { SALT_ROUNDS } from "./config.mjs";

const { Schema } = new DBLocal({ path: "./db" });

const User = Schema("User", {
  _id: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

export class UserRepository {
  constructor() {
    this.db = new DBLocal();
  }

  static async create({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    if (User.findOne({ username })) {
      throw new Error("Username already exists");
    }

    const id = crypto.randomBytes(16).toString("hex");
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    User.create({ _id: id, username, password: hashedPassword }).save();

    return id;
  }

  static async login({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    const user = User.findOne({ username });
    if (!user) {
      throw new Error("Invalid username or password");
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new Error("Invalid username or password");
    }

    const { password: _, ...publicUser } = user;
    return publicUser;
  }
}

class Validation {
  static username(username) {
    if (typeof username !== "string") {
      throw new Error("Invalid input");
    }
    if (username.length < 6) {
      throw new Error("Username must be at least 6 characters long");
    }
  }

  static password(password) {
    if (typeof password !== "string") {
      throw new Error("Invalid input");
    }
    if (password.length < 6) {
      throw new Error("Password must be at least 6 characters long");
    }
  }
}
