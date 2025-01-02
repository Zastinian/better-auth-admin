import { z } from "zod";
import { APIError } from "better-auth/api";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/plugins";
import { getSessionFromCtx } from "better-auth/api";
import type {
  BetterAuthPlugin,
  InferOptionSchema,
  AuthPluginSchema,
  Session,
  User,
  Where,
  GenericEndpointContext,
} from "better-auth/types";
import { deleteSessionCookie, setSessionCookie } from "better-auth/cookies";
import { generateId } from "better-auth";
import { getAdminAdapter } from "./adapter";

const getDate = (span: number, unit: "sec" | "ms" = "ms") => {
  return new Date(Date.now() + (unit === "sec" ? span * 1000 : span));
};

const getEndpointResponse = async <T>(ctx: {
  context: {
    returned?: unknown;
  };
}) => {
  const returned = ctx.context.returned;
  if (!returned) {
    return null;
  }
  if (returned instanceof Response) {
    if (returned.status !== 200) {
      return null;
    }
    return (await returned.clone().json()) as T;
  }
  if (returned instanceof APIError) {
    return null;
  }
  return returned as T;
};

export function mergeSchema<S extends AuthPluginSchema>(
  schema: S,
  newSchema?: {
    [K in keyof S]?: {
      modelName?: string;
      fields?: {
        [P: string]: string;
      };
    };
  },
) {
  if (!newSchema) {
    return schema;
  }
  for (const table in newSchema) {
    const newModelName = newSchema[table]?.modelName;
    if (newModelName) {
      schema[table].modelName = newModelName;
    }
    for (const field in schema[table].fields) {
      const newField = newSchema[table]?.fields?.[field];
      if (!newField) {
        continue;
      }
      schema[table].fields[field].fieldName = newField;
    }
  }
  return schema;
}

export interface UserWithRole extends User {
  roleId?: string | null;
  banned?: boolean | null;
  banReason?: string | null;
  banExpires?: Date | null;
}

export interface SessionWithImpersonatedBy extends Session {
  impersonatedBy?: string;
}

interface AdminOptions {
  /**
   * The default role for a user created by the admin
   *
   * @default "user"
   */
  defaultRole?: string | false;
  /**
   * The role required to access admin endpoints
   *
   * Can be an array of roles
   *
   * @default "admin"
   */
  adminRole?: string | string[];
  /**
   * A default ban reason
   *
   * By default, no reason is provided
   */
  defaultBanReason?: string;
  /**
   * Number of seconds until the ban expires
   *
   * By default, the ban never expires
   */
  defaultBanExpiresIn?: number;
  /**
   * Duration of the impersonation session in seconds
   *
   * By default, the impersonation session lasts 1 hour
   */
  impersonationSessionDuration?: number;
  /**
   * Permissions for the admin plugin
   */
  permissions?: {
    global?: string;
    createRole?: string;
    listPermissions?: string;
    listRoles?: string;
    updateRole?: string;
    getRole?: string;
    setRole?: string;
    banUser?: string;
    unBanUser?: string;
    impersonateUser?: string;
    stopImpersonating?: string;
    createUser?: string;
    updateUser?: string;
    deleteUser?: string;
    listUsers?: string;
    setUserRole?: string;
    listUserSessions?: string;
    revokeUserSession?: string;
    revokeUserSessions?: string;
    linkUser?: string;
    unlinkUser?: string;
    removeUser?: string;
    [key: string]: string | undefined;
  };
  /**
   * Custom schema for the admin plugin
   */
  schema?: InferOptionSchema<typeof schema>;
}

export const admin = <O extends AdminOptions>(options?: O) => {
  const defaultPermissions = {
    global: "*",
    createRole: "create_role",
    listPermissions: "list_permissions",
    listRoles: "list_roles",
    updateRole: "update_role",
    getRole: "get_role",
    setRole: "set_role",
    banUser: "ban_user",
    unBanUser: "un_ban_user",
    impersonateUser: "impersonate_user",
    stopImpersonating: "stop_impersonating",
    createUser: "create_user",
    updateUser: "update_user",
    deleteUser: "delete_user",
    listUsers: "list_users",
    setUserRole: "set_user_role",
    listUserSessions: "list_user_sessions",
    revokeUserSession: "revoke_user_session",
    revokeUserSessions: "revoke_user_sessions",
    linkUser: "link_user",
    unlinkUser: "unlink_user",
    removeUser: "remove_user",
  };

  const opts = {
    adminRole: "admin",
    defaultRole: "user",
    ...options,
    permissions: { ...defaultPermissions, ...options?.permissions },
  };

  const ERROR_CODES = {
    FAILED_TO_CREATE_USER: "Failed to create user",
    ERROR_FETCHING_DATA: "Error fetching data",
    USER_ALREADY_EXISTS: "User already exists",
    USER_NOT_FOUND: "User not found",
    USER_NOT_HAS_ROLE: "User does not have role",
    YOU_CANNOT_BAN_YOURSELF: "You cannot ban yourself",
    PERMISSION_DENIED: "Permission denied",
    ROLE_ALREADY_EXISTS: "Role already exists",
    ROLE_NOT_FOUND: "Role not found",
    UNAUTHORIZED: "Unauthorized",
  } as const;

  const permissionsToString = (permissions: string[]): string => permissions.join(",");

  const stringToPermissions = (permissions: string): string[] =>
    permissions ? permissions.split(",") : [];

  const checkPermission = async (ctx: GenericEndpointContext, requiredPermission: string) => {
    const user = ctx.context.session?.user as UserWithRole;
    if (!user.roleId) {
      throw new APIError("FORBIDDEN", {
        message: ERROR_CODES.USER_NOT_HAS_ROLE,
      });
    }
    const adapter = getAdminAdapter(ctx.context);
    const role = await adapter.findRoleById(user.roleId);
    if (!role) {
      throw new APIError("FORBIDDEN", {
        message: ERROR_CODES.PERMISSION_DENIED,
      });
    }
    if (role.name === opts.adminRole) {
      return;
    }
    const permissions = stringToPermissions(role.permissions);
    if (permissions.includes(opts.permissions.global)) {
      return;
    }
    if (!permissions.includes(requiredPermission)) {
      throw new APIError("FORBIDDEN", {
        message: ERROR_CODES.PERMISSION_DENIED,
      });
    }
  };

  const adminMiddleware = createAuthMiddleware(async (ctx) => {
    const session = await getSessionFromCtx(ctx);
    if (!session?.session) {
      throw new APIError("UNAUTHORIZED", {
        message: ERROR_CODES.UNAUTHORIZED,
      });
    }
    const user = session.user as UserWithRole;
    if (!user.roleId) {
      throw new APIError("FORBIDDEN", {
        message: ERROR_CODES.USER_NOT_HAS_ROLE,
      });
    }
    return { session: { user, session: session.session } };
  });
  return {
    id: "@hedystia/admin",
    init(ctx) {
      return {
        options: {
          databaseHooks: {
            user: {
              create: {
                async before(user) {
                  if (options?.defaultRole === false) return;
                  const adapter = getAdminAdapter(ctx);
                  let defaultRole = await adapter.findRoleByName(options?.defaultRole ?? "user");
                  if (!defaultRole) {
                    const role = await adapter.createRole({
                      role: {
                        id: generateId(),
                        name: options?.defaultRole ?? "user",
                        permissions: "",
                      },
                    });
                    defaultRole = role;
                  }
                  return {
                    data: {
                      roleId: defaultRole.id,
                      ...user,
                    },
                  };
                },
              },
            },
            session: {
              create: {
                async before(session) {
                  const user = (await ctx.internalAdapter.findUserById(
                    session.userId,
                  )) as UserWithRole;
                  if (user.banned) {
                    if (user.banExpires && user.banExpires.getTime() < Date.now()) {
                      await ctx.internalAdapter.updateUser(session.userId, {
                        banned: false,
                        banReason: null,
                        banExpires: null,
                      });
                      return;
                    }
                    return false;
                  }
                },
              },
            },
          },
        },
      };
    },
    hooks: {
      after: [
        {
          matcher(context) {
            return context.path === "/list-sessions";
          },
          handler: createAuthMiddleware(async (ctx) => {
            const response = await getEndpointResponse<SessionWithImpersonatedBy[]>(ctx);

            if (!response) {
              return;
            }
            const newJson = response.filter((session) => {
              return !session.impersonatedBy;
            });

            return ctx.json(newJson);
          }),
        },
      ],
    },
    endpoints: {
      createRole: createAuthEndpoint(
        "/admin/create-role",
        {
          method: "POST",
          body: z.object({
            name: z.string(),
            permissions: z.array(z.string()),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              description: "Create a role",
              responses: {
                200: {
                  description: "Success",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          role: {
                            $ref: "#/components/schemas/Role",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.createRole);
          const adapter = getAdminAdapter(ctx.context);
          const roleName = await adapter.findRoleByName(ctx.body.name);
          if (roleName) {
            throw new APIError("BAD_REQUEST", {
              message: ERROR_CODES.ROLE_ALREADY_EXISTS,
            });
          }
          const permissions = ctx.body.permissions.includes(opts.permissions.global)
            ? opts.permissions.global
            : permissionsToString(ctx.body.permissions);
          const role = await adapter.createRole({
            role: {
              id: generateId(),
              name: ctx.body.name,
              permissions: permissions,
            },
          });
          return ctx.json({ role });
        },
      ),
      listPermissions: createAuthEndpoint(
        "/admin/list-permissions",
        {
          method: "GET",
          use: [adminMiddleware],
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.listPermissions);
          return ctx.json({ permissions: opts.permissions });
        },
      ),
      listRoles: createAuthEndpoint(
        "/admin/list-roles",
        {
          method: "GET",
          use: [adminMiddleware],
          metadata: {
            openapi: {
              description: "List all roles",
              responses: {
                200: {
                  description: "Success",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          roles: {
                            type: "array",
                            items: {
                              $ref: "#/components/schemas/Role",
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.listRoles);
          const adapter = getAdminAdapter(ctx.context);
          const roles = await adapter.listRoles();
          return ctx.json({ roles });
        },
      ),
      updateRole: createAuthEndpoint(
        "/admin/update-role",
        {
          method: "POST",
          body: z.object({
            role: z.string(),
            permissions: z.array(z.string()),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              description: "Update a role",
              responses: {
                200: {
                  description: "Success",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          role: {
                            $ref: "#/components/schemas/Role",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.updateRole);
          const adapter = getAdminAdapter(ctx.context);
          const roleName = await adapter.findRoleByName(ctx.body.role);
          if (!roleName) {
            throw new APIError("BAD_REQUEST", {
              message: ERROR_CODES.ROLE_NOT_FOUND,
            });
          }
          const permissions = ctx.body.permissions.includes(opts.permissions.global)
            ? opts.permissions.global
            : permissionsToString(ctx.body.permissions);
          const role = await adapter.updateRole(roleName.id, {
            permissions,
          });
          return ctx.json({ role });
        },
      ),
      getRole: createAuthEndpoint(
        "/admin/get-role",
        {
          method: "POST",
          body: z.object({
            role: z.string({
              description: "The role to get. `admin` or `user` by default",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "getRole",
              summary: "Get a role",
              description: "Get a role",
              responses: {
                200: {
                  description: "Success",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          role: {
                            $ref: "#/components/schemas/Role",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.getRole);
          const adapter = getAdminAdapter(ctx.context);
          const role = await adapter.findRoleByName(ctx.body.role);
          if (!role) {
            throw new APIError("BAD_REQUEST", {
              message: ERROR_CODES.ROLE_NOT_FOUND,
            });
          }
          const permissions = stringToPermissions(role.permissions);
          const r = {
            ...role,
            permissions,
          };
          return ctx.json({ role: r });
        },
      ),
      setRole: createAuthEndpoint(
        "/admin/set-role",
        {
          method: "POST",
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
            role: z.string({
              description: "The role to set. `admin` or `user` by default",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "setRole",
              summary: "Set the role of a user",
              description: "Set the role of a user",
              responses: {
                200: {
                  description: "User role updated",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          user: {
                            $ref: "#/components/schemas/User",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.setRole);
          const adapter = getAdminAdapter(ctx.context);
          const role = await adapter.findRoleByName(ctx.body.role);
          if (!role) {
            throw new APIError("BAD_REQUEST", {
              message: ERROR_CODES.ROLE_NOT_FOUND,
            });
          }
          const updatedUser = await ctx.context.internalAdapter.updateUser(ctx.body.userId, {
            roleId: role.id,
          });
          return ctx.json({
            user: updatedUser as UserWithRole,
          });
        },
      ),
      createUser: createAuthEndpoint(
        "/admin/create-user",
        {
          method: "POST",
          body: z.object({
            email: z.string({
              description: "The email of the user",
            }),
            password: z.string({
              description: "The password of the user",
            }),
            name: z.string({
              description: "The name of the user",
            }),
            role: z.string({
              description: "The role of the user",
            }),
            /**
             * extra fields for user
             */
            data: z.optional(
              z.record(z.any(), {
                description: "Extra fields for the user. Including custom additional fields.",
              }),
            ),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "createUser",
              summary: "Create a new user",
              description: "Create a new user",
              responses: {
                200: {
                  description: "User created",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          user: {
                            $ref: "#/components/schemas/User",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.createUser);
          const existUser = await ctx.context.internalAdapter.findUserByEmail(ctx.body.email);
          if (existUser) {
            throw new APIError("BAD_REQUEST", {
              message: ERROR_CODES.USER_ALREADY_EXISTS,
            });
          }
          const user = await ctx.context.internalAdapter.createUser<UserWithRole>({
            email: ctx.body.email,
            name: ctx.body.name,
            role: ctx.body.role,
            ...ctx.body.data,
          });

          if (!user) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: ERROR_CODES.FAILED_TO_CREATE_USER,
            });
          }
          const hashedPassword = await ctx.context.password.hash(ctx.body.password);
          await ctx.context.internalAdapter.linkAccount({
            accountId: user.id,
            providerId: "credential",
            password: hashedPassword,
            userId: user.id,
          });
          return ctx.json({
            user: user as UserWithRole,
          });
        },
      ),
      listUsers: createAuthEndpoint(
        "/admin/list-users",
        {
          method: "GET",
          use: [adminMiddleware],
          query: z.object({
            searchValue: z
              .string({
                description: "The value to search for",
              })
              .optional(),
            searchField: z
              .enum(["email", "name"], {
                description: "The field to search in, defaults to email. Can be `email` or `name`",
              })
              .optional(),
            searchOperator: z
              .enum(["contains", "starts_with", "ends_with"], {
                description:
                  "The operator to use for the search. Can be `contains`, `starts_with` or `ends_with`",
              })
              .optional(),
            limit: z
              .string({
                description: "The number of users to return",
              })
              .or(z.number())
              .optional(),
            offset: z
              .string({
                description: "The offset to start from",
              })
              .or(z.number())
              .optional(),
            sortBy: z
              .string({
                description: "The field to sort by",
              })
              .optional(),
            sortDirection: z
              .enum(["asc", "desc"], {
                description: "The direction to sort by",
              })
              .optional(),
            filterField: z
              .string({
                description: "The field to filter by",
              })
              .optional(),
            filterValue: z
              .string({
                description: "The value to filter by",
              })
              .or(z.number())
              .or(z.boolean())
              .optional(),
            filterOperator: z
              .enum(["eq", "ne", "lt", "lte", "gt", "gte"], {
                description: "The operator to use for the filter",
              })
              .optional(),
          }),
          metadata: {
            openapi: {
              operationId: "listUsers",
              summary: "List users",
              description: "List users",
              responses: {
                200: {
                  description: "List of users",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          users: {
                            type: "array",
                            items: {
                              $ref: "#/components/schemas/User",
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.listUsers);
          const where: Where[] = [];
          const adapter = getAdminAdapter(ctx.context);

          if (ctx.query?.searchValue) {
            where.push({
              field: ctx.query.searchField || "email",
              operator: ctx.query.searchOperator || "contains",
              value: ctx.query.searchValue,
            });
          }

          if (ctx.query?.filterValue) {
            if (ctx.query.filterField === "role") {
              const role = await adapter.findRoleByName(String(ctx.query.filterValue));
              if (!role) {
                throw new APIError("BAD_REQUEST", {
                  message: ERROR_CODES.ROLE_NOT_FOUND,
                });
              }
              where.push({
                field: "roleId",
                operator: "eq",
                value: role.id,
              });
            } else {
              where.push({
                field: ctx.query.filterField || "email",
                operator: ctx.query.filterOperator || "eq",
                value: ctx.query.filterValue,
              });
            }
          }

          try {
            const users = await ctx.context.internalAdapter.listUsers(
              Number(ctx.query?.limit) || undefined,
              Number(ctx.query?.offset) || undefined,
              ctx.query?.sortBy
                ? {
                    field: ctx.query.sortBy,
                    direction: ctx.query.sortDirection || "asc",
                  }
                : undefined,
              where.length ? where : undefined,
            );
            return ctx.json({
              users: users as UserWithRole[],
            });
          } catch {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: ERROR_CODES.ERROR_FETCHING_DATA,
            });
          }
        },
      ),
      listUserSessions: createAuthEndpoint(
        "/admin/list-user-sessions",
        {
          method: "POST",
          use: [adminMiddleware],
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
          }),
          metadata: {
            openapi: {
              operationId: "listUserSessions",
              summary: "List user sessions",
              description: "List user sessions",
              responses: {
                200: {
                  description: "List of user sessions",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          sessions: {
                            type: "array",
                            items: {
                              $ref: "#/components/schemas/Session",
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.listUserSessions);
          const sessions = await ctx.context.internalAdapter.listSessions(ctx.body.userId);
          return {
            sessions: sessions,
          };
        },
      ),
      unBanUser: createAuthEndpoint(
        "/admin/un-ban-user",
        {
          method: "POST",
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "unBanUser",
              summary: "UnBan a user",
              description: "UnBan a user",
              responses: {
                200: {
                  description: "User unbanned",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          user: {
                            $ref: "#/components/schemas/User",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.unBanUser);
          const user = await ctx.context.internalAdapter.updateUser(ctx.body.userId, {
            banned: false,
          });
          return ctx.json({
            user: user,
          });
        },
      ),
      banUser: createAuthEndpoint(
        "/admin/ban-user",
        {
          method: "POST",
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
            /**
             * Reason for the ban
             */
            banReason: z
              .string({
                description: "The reason for the ban",
              })
              .optional(),
            /**
             * Number of seconds until the ban expires
             */
            banExpiresIn: z
              .number({
                description: "The number of seconds until the ban expires",
              })
              .optional(),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "banUser",
              summary: "Ban a user",
              description: "Ban a user",
              responses: {
                200: {
                  description: "User banned",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          user: {
                            $ref: "#/components/schemas/User",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.banUser);
          if (ctx.body.userId === ctx.context.session.user.id) {
            throw new APIError("BAD_REQUEST", {
              message: ERROR_CODES.YOU_CANNOT_BAN_YOURSELF,
            });
          }
          const user = await ctx.context.internalAdapter.updateUser(ctx.body.userId, {
            banned: true,
            banReason: ctx.body.banReason || options?.defaultBanReason || "No reason",
            banExpires: ctx.body.banExpiresIn
              ? getDate(ctx.body.banExpiresIn, "sec")
              : options?.defaultBanExpiresIn
                ? getDate(options.defaultBanExpiresIn, "sec")
                : undefined,
          });
          //revoke all sessions
          await ctx.context.internalAdapter.deleteSessions(ctx.body.userId);
          return ctx.json({
            user: user,
          });
        },
      ),
      impersonateUser: createAuthEndpoint(
        "/admin/impersonate-user",
        {
          method: "POST",
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "impersonateUser",
              summary: "Impersonate a user",
              description: "Impersonate a user",
              responses: {
                200: {
                  description: "Impersonation session created",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          session: {
                            $ref: "#/components/schemas/Session",
                          },
                          user: {
                            $ref: "#/components/schemas/User",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.impersonateUser);
          const targetUser = await ctx.context.internalAdapter.findUserById(ctx.body.userId);

          if (!targetUser) {
            throw new APIError("NOT_FOUND", {
              message: "User not found",
            });
          }

          const session = await ctx.context.internalAdapter.createSession(
            targetUser.id,
            undefined,
            true,
            {
              impersonatedBy: ctx.context.session.user.id,
              expiresAt: options?.impersonationSessionDuration
                ? getDate(options.impersonationSessionDuration, "sec")
                : getDate(60 * 60, "sec"), // 1 hour
            },
          );
          if (!session) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: ERROR_CODES.FAILED_TO_CREATE_USER,
            });
          }
          const authCookies = ctx.context.authCookies;
          deleteSessionCookie(ctx);
          await ctx.setSignedCookie(
            "admin_session",
            ctx.context.session.session.token,
            ctx.context.secret,
            authCookies.sessionToken.options,
          );
          await setSessionCookie(
            ctx,
            {
              session: session,
              user: targetUser,
            },
            true,
          );
          return ctx.json({
            session: session,
            user: targetUser,
          });
        },
      ),
      stopImpersonating: createAuthEndpoint(
        "/admin/stop-impersonating",
        {
          method: "POST",
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.stopImpersonating);
          const session = await getSessionFromCtx<
            // biome-ignore lint/complexity/noBannedTypes: <explanation>
            {},
            {
              impersonatedBy: string;
            }
          >(ctx);
          if (!session) {
            throw new APIError("UNAUTHORIZED", {
              message: ERROR_CODES.UNAUTHORIZED,
            });
          }
          if (!session.session.impersonatedBy) {
            throw new APIError("BAD_REQUEST", {
              message: "You are not impersonating anyone",
            });
          }
          const user = await ctx.context.internalAdapter.findUserById(
            session.session.impersonatedBy,
          );
          if (!user) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Failed to find user",
            });
          }
          const adminCookie = await ctx.getSignedCookie("admin_session", ctx.context.secret);
          if (!adminCookie) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Failed to find admin session",
            });
          }
          const adminSession = await ctx.context.internalAdapter.findSession(adminCookie);
          if (!adminSession || adminSession.session.userId !== user.id) {
            throw new APIError("INTERNAL_SERVER_ERROR", {
              message: "Failed to find admin session",
            });
          }
          await setSessionCookie(ctx, adminSession);
          return ctx.json(adminSession);
        },
      ),
      revokeUserSession: createAuthEndpoint(
        "/admin/revoke-user-session",
        {
          method: "POST",
          body: z.object({
            sessionToken: z.string({
              description: "The session token",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "revokeUserSession",
              summary: "Revoke a user session",
              description: "Revoke a user session",
              responses: {
                200: {
                  description: "Session revoked",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          success: {
                            type: "boolean",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.revokeUserSession);
          await ctx.context.internalAdapter.deleteSession(ctx.body.sessionToken);
          return ctx.json({
            success: true,
          });
        },
      ),
      revokeUserSessions: createAuthEndpoint(
        "/admin/revoke-user-sessions",
        {
          method: "POST",
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "revokeUserSessions",
              summary: "Revoke all user sessions",
              description: "Revoke all user sessions",
              responses: {
                200: {
                  description: "Sessions revoked",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          success: {
                            type: "boolean",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.revokeUserSessions);
          await ctx.context.internalAdapter.deleteSessions(ctx.body.userId);
          return ctx.json({
            success: true,
          });
        },
      ),
      removeUser: createAuthEndpoint(
        "/admin/remove-user",
        {
          method: "POST",
          body: z.object({
            userId: z.string({
              description: "The user id",
            }),
          }),
          use: [adminMiddleware],
          metadata: {
            openapi: {
              operationId: "removeUser",
              summary: "Remove a user",
              description: "Delete a user and all their sessions and accounts. Cannot be undone.",
              responses: {
                200: {
                  description: "User removed",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          success: {
                            type: "boolean",
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          await checkPermission(ctx, opts.permissions.deleteUser);
          await ctx.context.internalAdapter.deleteUser(ctx.body.userId);
          return ctx.json({
            success: true,
          });
        },
      ),
    },
    $ERROR_CODES: ERROR_CODES,
    schema: mergeSchema(schema, opts.schema),
  } satisfies BetterAuthPlugin;
};

const schema = {
  user: {
    fields: {
      roleId: {
        type: "string",
        required: false,
        input: false,
      },
      banned: {
        type: "boolean",
        defaultValue: false,
        required: false,
        input: false,
      },
      banReason: {
        type: "string",
        required: false,
        input: false,
      },
      banExpires: {
        type: "date",
        required: false,
        input: false,
      },
    },
  },
  session: {
    fields: {
      impersonatedBy: {
        type: "string",
        required: false,
      },
    },
  },
  role: {
    fields: {
      name: {
        type: "string",
        required: true,
      },
      permissions: {
        type: "string",
        required: true,
      },
    },
  },
} satisfies AuthPluginSchema;
