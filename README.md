<div align="center">
  <p>
    <strong>🛡️ @hedystia/better-auth-admin</strong>
  </p>

  <p>
    <strong>Enhance your Better Auth projects with powerful admin features! 🚀</strong>
  </p>

  <p>
    <a href="https://www.npmjs.com/package/@hedystia/better-auth-admin"><img src="https://img.shields.io/npm/v/@hedystia/better-auth-admin.svg?style=flat-square" alt="npm version"></a>
    <a href="https://www.npmjs.com/package/@hedystia/better-auth-admin"><img src="https://img.shields.io/npm/dm/@hedystia/better-auth-admin.svg?style=flat-square" alt="npm downloads"></a>
    <a href="https://github.com/Zastinian/better-auth-admin/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Zastinian/better-auth-admin.svg?style=flat-square" alt="license"></a>
  </p>
</div>

## 🌟 Features

- 🔐 **Role-based Access Control**: Define and manage user roles and permissions
- 👥 **Advanced User Management**: Create, update, list, and remove users with ease
- 🚫 **User Banning**: Temporarily or permanently restrict user access
- 👤 **User Impersonation**: Securely access user accounts for support purposes
- 🔍 **Flexible User Search**: Find users quickly with powerful search and filter options
- 🛠️ **Customizable Configuration**: Tailor the admin features to your project needs

## 🚀 Quick Start

1. Install the package:

```bash
npm install @hedystia/better-auth-admin
```

2. Import the plugin in your `auth.ts` file:

```typescript
import { admin } from "@hedystia/better-auth-admin";
import { betterAuth } from "better-auth";

export const auth = betterAuth({
  plugins: [
    // Other plugins...
    admin({
      // Configuration options
    }),
  ],
});
```

3. Add the plugin to your `authClient.ts` file:

```typescript
import { adminClient } from "@hedystia/better-auth-admin/client";
import { createAuthClient } from "better-auth/client";

export default createAuthClient({
  plugins: [
    // Other plugins...
    adminClient()
  ],
});
```

## 🎨 Configuration

The `admin` plugin accepts an optional configuration object with the following properties:

```typescript
admin({
  defaultRole: "user",
  adminRole: "admin",
  defaultBanReason: "No reason",
  defaultBanExpiresIn: 60 * 60 * 24 * 7, // 1 week
  impersonationSessionDuration: 60 * 60, // 1 hour
  permissions: {
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
  },
});
```

## 🌟 Why use this plugin?

This plugin is a fork of the original better-auth “admin” plugin but enhanced to support permissions for each role.

## 📝 License

This project is licensed under the [MIT License](LICENSE).

## 🙏 Acknowledgements

- [better-auth](https://github.com/better-auth/better-auth)
- [better-auth-admin](https://github.com/better-auth/better-auth/tree/main/packages/better-auth/src/plugins/admin)
