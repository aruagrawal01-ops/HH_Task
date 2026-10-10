// Self-check for the scam rules in index.html. Run: node test.js
const fs = require("fs");
const assert = require("assert");
const html = fs.readFileSync(__dirname + "/index.html", "utf8");
const code = html.match(/<script id="checker">([\s\S]*?)<\/script>/)[1];
const { EXAMPLES, checkMessage, adviceFor, pressureParts, secretParts, linkParts, tricksFound, trickParts } = new Function(code + "; return { EXAMPLES, checkMessage, adviceFor, pressureParts, secretParts, linkParts, tricksFound, trickParts };")();

const cases = [
  ["Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc.xyz/verify", "scam"],
  ["Congratulations! You won Rs 25,00,000 in the lucky draw. Pay processing fee to claim.", "scam"],
  ["Hi mum, this is my new number. I lost my phone, can you send money urgently?", "scam"],
  ["Your parcel is on hold at customs. Pay redelivery fee: bit.ly/3xYz", "scam"],
  ["Your OTP is 482913, share it with our agent to receive your refund.", "scam"],
  ["Check this out www.example.com", "suspicious"],
  ["Hey, are we still meeting for lunch at 1?", "safe"],
  ["Happy birthday! Have a great day 🎉", "safe"],
];
for (const [msg, want] of cases) {
  const got = checkMessage(msg).verdict;
  assert.strictEqual(got, want, `"${msg}" → ${got}, expected ${want}`);
}

const flagged = t => pressureParts(t).filter(p => p.flagged).map(p => p.text);
assert.deepStrictEqual(flagged("URGENT: pay within 24 hours or act now. Last chance, today only!"),
  ["URGENT", "within 24 hours", "act now", "Last chance", "today only"]);
assert.deepStrictEqual(flagged("Reply right now, immediately."), ["right now", "immediately"]);
assert.deepStrictEqual(flagged("See you at lunch"), []);
const msg = "Hi, urgent!\nCall me.";
assert.strictEqual(pressureParts(msg).map(p => p.text).join(""), msg); // nothing lost or reordered


// Private-details flag: asks are flagged, OTP deliveries and warnings are not.
const secrets = t => secretParts(t).filter(p => p.flagged).map(p => p.text);
const asks = [
  ["Please share the OTP you received to complete your refund.", ["OTP"]],
  ["Our executive will call you. Tell him your ATM PIN and CVV.", ["ATM PIN", "CVV"]],
  ["Send your Aadhaar number and PAN card photo to update KYC.", ["Aadhaar number", "PAN card"]],
  ["Reply with your card number and expiry date.", ["card number", "expiry date"]],
  ["Don't worry, just share the OTP with our agent.", ["OTP"]],
  ["I sent you a 6-digit code by mistake. Please send it to me.", ["6-digit code"]],
  ["What is your UPI PIN?", ["UPI PIN"]],
];
for (const [m, want] of asks) assert.deepStrictEqual(secrets(m), want, m);
const normal = [
  "Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank",
  "482913 is your OTP, don't share it with anyone.",
  "Never share your OTP, PIN or password with anyone.",
  "SBI never asks for your card details or CVV over phone or SMS.",
  "No bank will ask you to share your OTP.",
  "Use OTP 551204 to verify your Aadhaar. Valid for 10 minutes.",
  "Please send your address and pin code for delivery.",
];
for (const m of normal) {
  assert.deepStrictEqual(secrets(m), [], m);
  assert.strictEqual(checkMessage(m).verdict, "safe", m);
}
assert.strictEqual(checkMessage("Share the OTP to get your refund").verdict, "scam");


// Risky-link flag: shortened links, bait words in links, and "install this app to fix it".
const risky = t => linkParts(t).filter(p => p.flagged).map(p => p.text);
const linkCases = [
  ["Your parcel is held. Pay here: bit.ly/3xYz.", ["bit.ly/3xYz"]],
  ["Update now at https://sbi-kyc-update.com/login!", ["https://sbi-kyc-update.com/login"]],
  ["Claim your reward: www.flipkart-claim.in", ["www.flipkart-claim.in"]],
  ["Your account is blocked. Download the AnyDesk app to fix it.", ["Download the AnyDesk app"]],
  ["Install this app to complete your refund: refund-help.apk", ["Install this app", "refund-help.apk"]],
  ["Track your order at https://www.amazon.in/orders", []],
  ["Download the Swiggy app and get 20% off your first order.", []],
];
for (const [m, want] of linkCases) assert.deepStrictEqual(risky(m), want, m);
assert.strictEqual(checkMessage("Update now at https://sbi-kyc-update.com/login").verdict, "scam");


// Money tricks: each message names its kind of scam and highlights the phrase.
const tricks = t => tricksFound(t).map(x => x.name);
const marked = t => trickParts(t).filter(p => p.flagged).map(p => p.text);
const trickCases = [
  ["Congratulations! You won a lottery of Rs 25 lakh.", ["Prize or lottery scam"], ["You won", "lottery"]],
  ["Your account will be blocked unless you update your KYC.", ["Account block or KYC scam"], ["account will be blocked", "KYC"]],
  ["Your parcel is stuck. Pay a small fee of Rs 25 to release it.", ["Parcel fee scam"], ["parcel is stuck", "small fee"]],
  ["Dear consumer, your electricity will be cut off tonight at 9:30.", ["Electricity bill scam"], ["electricity will be cut off"]],
  ["Earn 5000 per day working from home! Pay registration fee of Rs 500.", ["Work-from-home job scam"], ["Earn 5000 per day", "working from home", "registration fee"]],
  ["We can do typecasting from home and earn up to 25k.", ["Work-from-home job scam"], ["typecasting from home", "earn up to 25k"]],
  ["Work in this company and earn 30k per month.", ["Work-from-home job scam"], ["earn 30k per month"]],
  ["For help, call our officer on 98765 43210.", ["Unknown phone number"], ["call our officer on 98765 43210"]],
  ["See you at lunch, call me when you're free.", [], []],
  ["Congratulations on your wedding! Sorry, I was typing on the bus.", [], []],
  ["I blocked him on Instagram.", [], []],
];
for (const [m, names, phrases] of trickCases) {
  assert.deepStrictEqual(tricks(m), names, m);
  assert.deepStrictEqual(marked(m), phrases, m);
}
for (const [m] of trickCases.slice(0, 7)) assert.notStrictEqual(checkMessage(m).verdict, "safe", m);
for (const [m] of trickCases.slice(4, 7)) assert.strictEqual(checkMessage(m).verdict, "scam", m); // job offers alone are scams


// Risk score: 0-100, combos add a bonus, thresholds at 30 and 60.
const scoreOf = t => checkMessage(t).score;
assert.strictEqual(scoreOf("Hey, are we still meeting for lunch at 1?"), 0);
assert.strictEqual(scoreOf("Check this out www.example.com"), 30);                 // a plain link: be careful
assert.strictEqual(scoreOf("Your electricity will be cut off tonight."), 35);
assert.strictEqual(scoreOf("Earn 30k per month."), 65);                             // job offer alone: likely scam
assert.ok(scoreOf("Your parcel is stuck. Pay here: bit.ly/x") >                     // link + money story + 2 kinds
  scoreOf("Your parcel is stuck.") + scoreOf("Pay here: bit.ly/x"));
assert.strictEqual(scoreOf("URGENT! You won a lottery. Share OTP at bit.ly/x to claim prize. Call 98765 43210 now."), 100); // capped
for (const [m] of [...cases, ...trickCases]) { const s = scoreOf(m); assert.ok(s >= 0 && s <= 100, m); }


// Findings list: exact words spotted, and advice that fits what was found.
const r = checkMessage("URGENT: your parcel is stuck. Pay a small fee at bit.ly/pay or call 98765 43210.");
const byTitle = Object.fromEntries(r.findings.map(f => [f.title, f.words]));
assert.deepStrictEqual(byTitle["Rushing you"], ["URGENT"]);
assert.deepStrictEqual(byTitle["Shortened link"], ["bit.ly/pay"]);
assert.deepStrictEqual(byTitle["Unknown phone number"], ["call 98765 43210"]);
assert.ok(r.findings.every(f => f.why && f.title));
const adv = adviceFor(r).join(" ");
for (const must of ["Don't reply", "Don't click any links", "Don't share any OTP", "Don't pay", "Block the sender"]) assert.ok(adv.includes(must), must);
assert.ok(!adv.includes("install"));                                   // no app mentioned, no app advice
assert.deepStrictEqual(adviceFor(checkMessage("See you at lunch")), []);  // safe: no advice


// Demo buttons: scam examples must say "Likely a scam", safe ones "Looks safe".
for (const [label, kind, m] of EXAMPLES) {
  const { verdict, score } = checkMessage(m);
  assert.strictEqual(verdict, kind === "scam" ? "scam" : "safe", `${label}: ${verdict} (${score})`);
}


// Report box and honest note are in the page with the exact wording.
assert.ok(html.includes("the National Cyber Crime Helpline, or visit"));
assert.ok(html.includes("This tool catches common scams and tricks, but not every scam. Always be careful while sharing details and looking at random and scam-like messages in your messages app."));

console.log(`All ${EXAMPLES.length} demo checks, 10 list/advice checks, 7 score checks and ${cases.length + 4 + asks.length + normal.length + 1 + linkCases.length + 1 + trickCases.length + 10} checks passed`);
