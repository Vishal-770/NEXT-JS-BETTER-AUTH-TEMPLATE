import { betterAuth } from "better-auth";
import { and, eq } from "drizzle-orm";

import { sendEmailVerification } from "../services/SendEmail";
import { sendPasswordResetEmail } from "../services/SendPasswordResetEmail";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { db } from "../drizzle/db";
import * as schema from "../drizzle/schema";

export const auth = betterAuth({
  experimental: { joins: true },
  emailVerification: {
    sendVerificationEmail: async ({ user, url }) => {
      void sendEmailVerification(user.email, user.name, url);
    },
    sendOnSignIn: true,
    autoSignInAfterVerification: true,
  },
  socialProviders: {
    github: {
      clientId: process.env.GITHUB_CLIENT_ID as string,
      clientSecret: process.env.GITHUB_CLIENT_SECRET as string,
    },
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    },
  },
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,
    autoSignIn: false,
    sendResetPassword: async ({ user, url }) => {
      void sendPasswordResetEmail(user.email, user.name, url);
    },
  },
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: schema,
  }),

  account: {
    accountLinking: {
      enabled: true,
      trustedProviders: ["email"],
    },
  },

  // Use databaseHooks to handle unverified email takeover
  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          // Check if there's an existing unverified user with this email
          const existingUser = await db
            .select()
            .from(schema.user)
            .where(
              and(
                eq(schema.user.email, user.email),
                eq(schema.user.emailVerified, false)
              )
            )
            .limit(1);

          if (existingUser.length > 0) {
            const userId = existingUser[0].id;
            // Delete the unverified account so the new user can register
            await db.delete(schema.user).where(eq(schema.user.id, userId));
            // Also delete any associated sessions and accounts
            await db
              .delete(schema.session)
              .where(eq(schema.session.userId, userId));
            await db
              .delete(schema.account)
              .where(eq(schema.account.userId, userId));
          }

          // Return the user data wrapped in { data: user }
          return { data: user };
        },
      },
    },
  },
});
