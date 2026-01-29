V66 - Balance direction fix

What changed:
- Screen 2 (BALANCE) direction mapping is corrected:
  - Anchor=VAL -> LONG
  - Anchor=VAH -> SHORT

Install:
1) Stop server (Ctrl+C)
2) Copy server.js into your current working journal folder (overwrite)
3) Start: npm start

Note:
If you already have an in-progress session in the browser, refresh and re-enter Screen 2, or clear the session cookie (open in an incognito window) to see the updated direction immediately.
