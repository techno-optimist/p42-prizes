import { appendPortalEvent, updatePortalState } from "../src/lib/portal-store";

const [, , statePath, prefix, countRaw] = process.argv;
const count = Number(countRaw);
if (!statePath || !prefix || !Number.isSafeInteger(count) || count < 1 || count > 1_000) {
  throw new Error("portal store worker arguments are invalid");
}
process.env.P42_PORTAL_STATE_PATH = statePath;
process.env.P42_PORTAL_STATE_LOCK_TIMEOUT_MS = "10000";

for (let index = 0; index < count; index += 1) {
  updatePortalState((state) => {
    appendPortalEvent(state, {
      type: "verification.completed",
      subjectId: `${prefix}-${index}`,
      payload: { prefix, index },
    });
  });
}
