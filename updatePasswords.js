const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const readline = require("readline");

// MongoDB connection
mongoose.connect("mongodb+srv://padariyasunny:NJUdakluqHXMtejz@yt.1qrya.mongodb.net/Inventory", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("Connected to MongoDB"))
.catch((err) => console.error("Error connecting to MongoDB:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["Admin", "Manager", "Viewer"], required: true, default: "Viewer" },
});

const User = mongoose.model("User", userSchema);

// Setup readline for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

async function updatePasswords() {
  try {
    const users = await User.find();
    if (users.length === 0) {
      console.log("No users found in the database.");
      return;
    }

    for (const user of users) {
      await new Promise((resolve) => {
        rl.question(`Enter new password for ${user.email}: `, async (password) => {
          if (!password) {
            console.log("Password cannot be empty. Skipping user.");
          } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
            await user.save();
            console.log(`Password updated for ${user.email}`);
          }
          resolve();
        });
      });
    }
  } catch (error) {
    console.error("Error updating passwords:", error);
  } finally {
    rl.close();
    mongoose.disconnect();
  }
}

updatePasswords();
