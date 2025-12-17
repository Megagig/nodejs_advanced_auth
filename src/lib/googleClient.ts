import { OAuth2Client } from "google-auth-library";

export function getGoogleClient() {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;

    if (!clientId || !clientSecret) {
        throw new Error("Google OAuth credentials missing");
    }

    return new OAuth2Client(
        clientId,
        clientSecret,
        redirectUri
    );
}
