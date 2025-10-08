// models/Vault.js
import mongoose from "mongoose";

const vaultSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  password: { type: String, required: true },
});

const Vault = mongoose.model("Vault", vaultSchema);
export default Vault;
