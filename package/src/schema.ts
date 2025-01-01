import { z } from "zod";
import { generateId } from "better-auth";

export const roleSchema = z.object({
  id: z.string().default(generateId),
  name: z.string(),
  permissions: z.string(),
});

export type Role = z.infer<typeof roleSchema>;
