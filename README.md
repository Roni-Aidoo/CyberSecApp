# LFY: link verifier with real threat intelligence

Checks each link against **VirusTotal** (70+ security vendors) and **Google Safe Browsing**,
reads the site's real title/description for the "About URL" section, and merges that with
LFY's on-device phishing/malware/ransomware pattern checks.

## Run it
1. Install Node.js 20.6 or newer.
2. Get keys: VirusTotal (free account > profile > API key) and Google Safe Browsing
   (Google Cloud Console > enable "Safe Browsing API" > create an API key). Either one works alone.
3. In this folder:
   ```
   cp .env.example .env     # then paste your keys into .env
   npm install
   npm start
   ```
4. Open http://localhost:3000 on your computer. To test on your phone, use your computer's
   local IP (e.g. http://192.168.x.x:3000) on the same Wi-Fi. Camera scanning needs HTTPS
   except on localhost, so deploy for real phone use.

## Deploy
Render, Railway or Fly.io all work: connect the folder, set `VT_API_KEY` and `SB_API_KEY`
as environment variables, start command `npm start`. You get HTTPS automatically, which
the QR camera and clipboard features need.

## Things to know
- **Quotas:** VirusTotal's free key allows about 4 requests/minute and 500/day, and is for
  non-commercial use only. Results are cached for 1 hour and each IP is limited to 15 checks/minute.
  For a public or commercial app you need a paid VirusTotal plan. Check Google's Safe Browsing
  terms too.
- **Privacy:** every link a user checks is sent to VirusTotal and Google. Say so in your privacy policy.
  Never put API keys in front-end code.
- **Safety:** the server only fetches public websites (private and internal addresses are
  blocked) with a 5 s timeout and 200 KB cap. If you host it publicly, also put it behind
  your platform's DDoS/rate protection.
- **Accuracy:** no checker is perfect. A brand-new phishing page may not be listed anywhere yet,
  which is why LFY also runs its own pattern checks.
