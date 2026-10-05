const nodemailer = require("nodemailer");

let transporter;

function getTransporter() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass || !process.env.EMAIL_FROM) {
    const error = new Error("Email delivery is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS, and EMAIL_FROM.");
    error.code = "EMAIL_NOT_CONFIGURED";
    throw error;
  }
  if (!transporter) {
    const port = Number(process.env.SMTP_PORT || 2525);
    transporter = nodemailer.createTransport({
      host,
      port,
      secure: process.env.SMTP_SECURE === "true" || port === 465,
      auth: { user, pass },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });
  }
  return transporter;
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

function baseUrl() {
  const renderUrl = process.env.RENDER_EXTERNAL_URL || (process.env.RENDER_EXTERNAL_HOSTNAME && `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`);
  return (process.env.APP_BASE_URL || renderUrl || `http://localhost:${process.env.PORT || 10000}`).replace(/\/+$/, "");
}

async function sendEmail({ to, subject, text, html }) {
  return getTransporter().sendMail({ from: process.env.EMAIL_FROM, to, subject, text, html });
}

async function sendVerificationEmail(user, token) {
  const url = `${baseUrl()}/verify-email.html?token=${encodeURIComponent(token)}`;
  const name = escapeHtml(user.fullName);
  await sendEmail({
    to: user.email,
    subject: "Verify your Cypher-School email",
    text: `Hello ${user.fullName},\n\nVerify your email within 24 hours: ${url}\n\nIf you did not create this account, ignore this email.`,
    html: `<main style="font-family:Arial,sans-serif;max-width:560px;margin:40px auto;color:#173044"><h1>Welcome to Cypher-School</h1><p>Hello ${name},</p><p>Confirm your email address to activate your account.</p><p><a href="${url}" style="display:inline-block;padding:12px 18px;background:#18b9d2;color:#03101c;text-decoration:none;border-radius:6px">Verify email</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this message.</p></main>`,
  });
}

async function sendPasswordResetEmail(user, token) {
  const url = `${baseUrl()}/reset-password.html?token=${encodeURIComponent(token)}`;
  const name = escapeHtml(user.fullName);
  await sendEmail({
    to: user.email,
    subject: "Reset your Cypher-School password",
    text: `Hello ${user.fullName},\n\nReset your password within 30 minutes: ${url}\n\nIf you did not request this, ignore this email; your password will not change.`,
    html: `<main style="font-family:Arial,sans-serif;max-width:560px;margin:40px auto;color:#173044"><h1>Password reset</h1><p>Hello ${name},</p><p>Use the secure link below to choose a new password.</p><p><a href="${url}" style="display:inline-block;padding:12px 18px;background:#18b9d2;color:#03101c;text-decoration:none;border-radius:6px">Reset password</a></p><p>This link expires in 30 minutes and works once. If you did not request this, ignore this email.</p></main>`,
  });
}

async function sendPasswordChangedEmail(user) {
  const name = escapeHtml(user.fullName);
  await sendEmail({
    to: user.email,
    subject: "Your Cypher-School password was changed",
    text: `Hello ${user.fullName},\n\nYour Cypher-School password was changed. If this was not you, use the password recovery page immediately.`,
    html: `<main style="font-family:Arial,sans-serif;max-width:560px;margin:40px auto;color:#173044"><h1>Password updated</h1><p>Hello ${name},</p><p>Your Cypher-School password was changed. If you did not make this change, start password recovery immediately.</p></main>`,
  });
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail, sendPasswordChangedEmail };
