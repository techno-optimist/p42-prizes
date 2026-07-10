import { json } from "@/lib/api";
import { mutationApiCapabilities } from "@/lib/api-auth";

// Configuration is read at request time so agents never receive build-time state.
export const dynamic = "force-dynamic";

export function GET() {
  return json({
    api_version: "p42-prizes-capabilities-v1",
    mutations: mutationApiCapabilities(),
  });
}
