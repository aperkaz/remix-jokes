import bcrypt from "bcryptjs";
import { createCookieSessionStorage, redirect } from "remix";

import { db } from "./db.server";

export const login = async (
  username: string,
  password: string
): Promise<{ id: string; username: string } | null> => {
  const userInDb = await db.user.findUnique({
    where: {
      username,
    },
  });
  if (!userInDb) return null;

  const passwordMatch = await bcrypt.compare(password, userInDb.passwordHash);
  if (!passwordMatch) return null;

  return { id: userInDb.id, username: userInDb.username };
};

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  throw new Error("SESSION_SECRET must be set");
}

const storage = createCookieSessionStorage({
  cookie: {
    name: "RJ_session",
    // normally you want this to be `secure: true`
    // but that doesn't work on localhost for Safari
    // https://web.dev/when-to-use-local-https/
    secure: process.env.NODE_ENV === "production",
    secrets: [sessionSecret],
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true,
  },
});

export async function createUserSession(userId: string, redirectTo: string) {
  const session = await storage.getSession();
  session.set("userId", userId);
  return redirect(redirectTo, {
    headers: {
      "Set-Cookie": await storage.commitSession(session),
    },
  });
}
