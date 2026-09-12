---
document_id: KB-012
title: VPN Connection Guide
category: guide
allowed_roles:
  - employee
  - it
  - security
version: "1.4"
last_reviewed: "2024-01-30"
owner: IT Service Management
summary: >-
  Employee self-service guide for connecting to the corporate VPN: setup,
  first-line checks when it will not connect, and when to contact the service
  desk.
---

# VPN Connection Guide (Employee Guide)

> **Simulated content.** Fictional sample documentation for a demonstration
> system.

## 1. Before you start

You need:

* a company-managed device with the approved VPN client installed;
* an active account with the VPN entitlement;
* MFA enrolled on your authenticator app or hardware key;
* a working internet connection.

## 2. Connecting

1. Open the VPN client from the start menu or the tray icon.
2. Select the **corporate gateway** profile (do not create your own profile).
3. Choose "Connect". Enter your company credentials when prompted — the client
   should use single sign-on, so you normally see a browser sign-in window
   instead.
4. Approve the MFA prompt on your registered device.
5. Wait for the status to change to **Connected**. The icon turns green and the
   client shows an assigned internal address.

## 3. First-line checks if it will not connect

Work through these in order — they resolve most cases.

1. **Check your internet connection first.** Open a public website in a browser.
   If the internet is down, the VPN cannot connect either.
2. **Check your credentials.** Sign in to the company single sign-on portal. If
   that fails, your password has expired, or your account is locked — reset or
   unlock it, then retry the VPN.
3. **Check the MFA prompt.** If you did not receive a prompt, open the
   authenticator app and make sure the device time is set to automatic. An
   out-of-sync clock is a common cause.
4. **Restart the client.** Fully quit it (including from the tray) and start it
   again.
5. **Restart the device** if the client reports a network adapter error.
6. **Try a different network.** Switch to a mobile hotspot. If the VPN works
   there, your home router or internet provider is blocking the connection.
7. **Check the status page** for a known outage before assuming the problem is
   yours.

## 4. Common messages and what they mean

| Message | Likely cause | What to do |
| ------- | ------------ | ---------- |
| "Authentication failed" | Wrong password, expired password, or a rejected MFA prompt | Sign in to single sign-on to check the credential; retry MFA |
| "Unable to reach the server" | Local network, DNS or a gateway outage | Check your internet, try a hotspot, check the status page |
| "Connected, no traffic" | Corrupt virtual network adapter | Restart the device; if it persists, contact the service desk |
| "Certificate error" | Device certificate expired, or the clock is wrong | Set the clock to automatic; contact the service desk to re-enrol |
| "Client version not supported" | Outdated VPN client | Update the client from the software catalogue |

## 5. Working while connected

* Keep the VPN connected whenever you access internal systems.
* Do not disable the VPN "to make the internet faster".
* If the connection drops repeatedly, note the times — that pattern helps the
  service desk.
* Do not use a personal VPN product at the same time.

## 6. When to contact the IT service desk

Contact the service desk if:

* the first-line checks did not resolve the problem;
* the client reports a certificate or licence error;
* several colleagues cannot connect at the same time;
* the connection drops repeatedly at the same times of day;
* you are travelling and the local network blocks the connection even on a
  hotspot.

Include your device name, the exact error message, the time it happened, and
whether you were on home Wi-Fi or a mobile hotspot.

## 7. Security reminder

The VPN client will never ask you to install an extra "update" from an email
link, and the service desk will never ask for your password or an MFA code. If
someone does, report it to the security team immediately.
