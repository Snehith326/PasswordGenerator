// routes/vault.js
import express from "express";
import Vault from "../models/Vault.js";
import authMiddleware from "../middleware/authmiddleware.js"; // JWT middleware
import { encrypt, decrypt } from "../utils/crypto.js";

const router = express.Router();

// ✅ Add a new password
router.post("/", authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;
    const encryptedPassword=encrypt(password);
    const newPassword = new Vault({
      userId: req.user.id,
      password:encryptedPassword,
    });
    await newPassword.save();
    res.status(201).json(newPassword);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Fetch all passwords for logged-in user
router.get("/", authMiddleware, async (req, res) => {
  try {
    const passwords = await Vault.find({ userId: req.user.id });
    const decryptedPasswords = passwords.map((password) => ({
      ...password._doc,
      password: decrypt(password.password),
    }));
res.json(decryptedPasswords);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Edit a password
router.put("/:id", authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;
    const encryptedPassword = encrypt(password);
    const updated = await Vault.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { password: encryptedPassword },
      { new: true }
    );
    res.json({
      ...updated._doc,
      password: decrypt(updated.password),
    });
    if (!updated) return res.status(404).json({ message: "Password not found" });
    res.json(updated);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Delete a password
router.delete("/:id", authMiddleware, async (req, res) => {
  try {
    const deleted = await Vault.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!deleted) return res.status(404).json({ message: "Password not found" });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
