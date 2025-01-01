import type { AuthContext } from "better-auth/types";
import type { Role } from "./schema";

export const getAdminAdapter = (context: AuthContext) => {
  const adapter = context.adapter;
  return {
    findRoleById: async (roleId: string) => {
      const role = await adapter.findOne<Role>({
        model: "role",
        where: [
          {
            field: "id",
            value: roleId,
          },
        ],
      });
      if (!role) {
        return null;
      }
      return {
        ...role,
      };
    },
    findRoleByName: async (name: string) => {
      const role = await adapter.findOne<Role>({
        model: "role",
        where: [
          {
            field: "name",
            value: name,
          },
        ],
      });
      if (!role) {
        return null;
      }
      return {
        ...role,
      };
    },
    createRole: async (data: {
      role: Role;
    }) => {
      const role = await adapter.create<Role>({
        model: "role",
        data: {
          ...data.role,
        },
      });
      return role;
    },
    listRoles: async () => {
      const roles = await adapter.findMany<Role>({
        model: "role",
      });
      return roles;
    },
    updateRole: async (roleId: string, data: Partial<Role>) => {
      const role = await adapter.update<Role>({
        model: "role",
        where: [
          {
            field: "id",
            value: roleId,
          },
        ],
        update: {
          ...data,
        },
      });
      return role;
    },
  };
};
