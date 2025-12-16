// src/lib/email.ts
import nodemailer from "nodemailer";

interface EmailOptions {
    to: string;
    subject: string;
    html: string;
}

// Function to send the email
export const sendEmail = async ({ to, subject, html }: EmailOptions) => {
    // 1. Check for required environment variables (Safeguard)
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
        console.log("Email ENV variables (HOST, USER, or PASS) are not present.");
        return; // Stop execution if credentials are missing
    }

    // 2. Define Transporter Configuration
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || "587"), // Use 587 or the one specified in .env
        secure: false, // Use 'false' for 587 (TLS) or Mailtrap
        // from: process.env.EMAIL_FROM,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },

    });

    // 3. Send the Mail
    await transporter.sendMail({
        from: process.env.MAIL_FROM || "no-reply@example.com", // Sender address
        to: to, // Recipient email
        subject: subject, // Email subject
        html: html, // HTML content of the email
    });
};