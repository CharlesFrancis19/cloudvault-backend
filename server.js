import express from "express";
import cors from "cors";
import morgan from "morgan";
import { env } from "./config/env.js";
import { requireAuth, sameOrgGuard } from "./middleware/auth.js";

import health from "./routes/health.js";
import auth from "./routes/auth.js";
import files from "./routes/files.js";
import shares from "./routes/shares.js";
import audit from "./routes/audit.js";
import adminOrg from "./routes/admin-org.js";
import adminPlatform from "./routes/admin-platform.js";
import profile from "./routes/profile.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(morgan("dev"));

app.use("/health", health);
app.use("/auth", auth);

// Protected
app.use("/api", requireAuth, sameOrgGuard);
app.use("/api/files", files);
app.use("/api/shares", shares);
app.use("/api/audit", audit);
app.use("/api/profile", profile);
app.use("/api/admin/org", adminOrg);
app.use("/api/admin/platform", adminPlatform);

app.listen(env.port, () => {
  console.log(`SecureVault backend listening on :${env.port} (mode=${env.authMode})`);
});
