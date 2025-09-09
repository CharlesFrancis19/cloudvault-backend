import { Router } from "express";
import { requireRole } from "../middleware/auth.js";
import { setOrgPolicy, writeAudit } from "../services/dynamo.js";

const r = Router();

r.use(requireRole("org_admin"));

r.put("/policy", async (req, res) => {
  const user = req.user;
  await setOrgPolicy(user.orgId, req.body);
  await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "ORG_POLICY_UPDATE", targetType: "ORG", outcome: "OK" });
  res.json({ ok: true });
});

r.get("/usage", async (_req, res) => {
  res.json({ note: "Add S3 inventory / scheduled job for org usage aggregation." });
});

export default r;
