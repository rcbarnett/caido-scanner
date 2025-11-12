import type { Preset } from "shared";

import { Checks } from "../../checks";

export const HEAVY_PRESET: Preset = {
  name: "Heavy",
  active: (Object.values(Checks) as string[]).map((checkID) => ({
    checkID,
    enabled: true,
  })),
  passive: (Object.values(Checks) as string[]).map((checkID) => ({
    checkID,
    enabled: true,
  })),
};
