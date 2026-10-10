# HH_Task
A scam message checker built entirely by voice with Wispr Flow. Paste a WhatsApp or SMS message and it flags pressure tricks, fake links and requests for OTPs, with a risk score. Runs on your device with no API keys.


# Scam Message Checker

Paste a suspicious WhatsApp or SMS message and find out if it looks like a scam.

**Built entirely by voice.** Every line of this project was created by speaking prompts with [Wispr Flow](https://wisprflow.ai) into Claude Code. No code was typed by hand.

## What it does

- Highlights warning signs directly in the message
- Gives a risk score from 0 to 100 (Looks Safe, Be Careful, Likely a Scam)
- Explains each red flag in plain language
- Tells you what to do next, and where to report a scam in India
- Includes example scam and safe messages to try

## What it looks for

| Red flag | Examples |
|----------|----------|
| Pressure | "urgent", "immediately", "within 24 hours", "last chance" |
| Private details | Asking you to share an OTP, PIN, password, card number, CVV, Aadhaar or PAN |
| Dodgy links | Short links, links with words like "kyc" or "claim", app install requests |
| Money tricks | Fake prizes, "account will be blocked", parcel fees, electricity cut-off threats, work-from-home offers with a fee |

A message that only gives you an OTP and says "do not share it" is treated as normal, not as a scam.

## How it works

The checker matches messages against lists of common scam patterns. Each flag adds points, and several kinds of tricks together add more.

- No AI service, no API key, no account
- Everything runs in your browser
- Your message is never sent anywhere

## How to run

1. Download or clone this repository.
2. Open `index.html` in your browser.
3. Paste a message and press **Check**, or click one of the example buttons.

## Limitations

This tool catches common scam tricks, not every scam. A clever scam can look safe here, and a normal message can occasionally be flagged. Always be careful with unexpected messages.

## If you get a scam message

In India, call **1930** (the national cyber crime helpline) or visit **cybercrime.gov.in**. If you already shared a code or paid money, call your bank right away.

## How it was built

This project was made for the Wispr Flow shortlisting task: build something real using only your voice. The full screen recording shows the build from an empty folder to the working app.

## Author

Arush Agrawal
