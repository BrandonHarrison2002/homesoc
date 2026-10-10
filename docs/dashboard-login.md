# Private dashboard login

HomeSOC now has one dashboard account. All inventory, logs, alerts, incidents, summary, health, and mutation routes require a valid login. Login and logout use the existing CSRF protection. Ordinary unauthenticated reads redirect to login; unauthenticated writes are rejected without applying them. Missing, malformed, unreadable, or incorrectly permissioned credentials fail closed with a setup message.

## Set or reset the password

Run as `brandon` in the Pi SSH terminal, without sudo:

```bash
cd ~/homesoc
.venv/bin/python dashboard/auth.py set-password --username brandon
```

The command asks for the password twice without echoing it. Choose 12–128 characters. The username supports letters, digits, dots, underscores, and hyphens. The password is stored as a salted PBKDF2-SHA256 hash with 600,000 iterations using Werkzeug, already installed with Flask. `dashboard-state/auth.json` is private mode 600, in the ignored private state directory. No password, hash, or session key belongs in Git or screenshots.

Every reset changes a credential version. Previous signed login sessions are rejected on their next request. Password reset does not require a service restart. Five failed login attempts within ten minutes temporarily block login for all browsers; wait for the window to expire. This throttle is bounded, process-local, and resets on restart. It is not a distributed protection system, and concurrent attempts may reach verification before the limit is recorded.

## Access from Windows through SSH

The dashboard binds only to `127.0.0.1:8080` on the Pi. Direct access through `http://192.168.8.165:8080` stops working by design. In a separate Windows PowerShell window:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18080:127.0.0.1:8080 brandon@192.168.8.165
```

Keep that window open. It may look idle; `-N` requests forwarding without opening a shell. Open **http://127.0.0.1:18080/** in your Windows browser and sign in. This browser URL is local to the PC running the tunnel. Close the tunnel with Ctrl+C when finished. The existing SSH key-based Pi login is unchanged.

SSH encrypts the Windows-to-Pi connection, while browser-to-local-tunnel traffic uses loopback HTTP. The cookie intentionally does not use Secure in this setup because the browser URL is HTTP; it uses HttpOnly, SameSite=Strict, a dedicated cookie name, and an eight-hour absolute expiry. Session activity does not extend that expiry. Do not rebind this HTTP server to the LAN to enter passwords; a future private HTTPS reverse proxy would need separate configuration and Secure cookies.

## Sessions and recovery

Login replaces the pre-login session and rotates its CSRF token. Log out uses POST with CSRF and clears this browser's cookie. Protected responses use no-store to reduce cached private content, and framing is disabled. Flask sessions are signed cookies, not encrypted data or server-side sessions. A copied valid cookie remains usable until expiry or a credential reset; browser logout alone does not centrally revoke copies. Reset the password to invalidate existing login sessions.

The current backup script excludes authentication credentials and the Flask session key. Recreate credentials with the CLI after recovery. Losing the session key signs users out; it does not erase incidents. This login is for one operator, without account roles, multi-user administration, or a complete authentication audit system. It does not turn the existing Flask development server into a production WSGI deployment.

If the browser cannot connect, confirm the SSH tunnel remains open and use these commands on the Pi:

```bash
sudo systemctl status homesoc-dashboard --no-pager
ss -ltn 'sport = :8080'
curl -I http://127.0.0.1:8080/login
```

Expected listener: `127.0.0.1:8080`; login returns 200 after valid credential setup. A 503 setup page means inspect the private file permissions/ownership or rerun the CLI as the dashboard user. Do not print the credential file into chat.

## Validation

67 dashboard tests cover the previous features plus credential privacy, route protection, CSRF, login/logout, cookie flags, eight-hour expiry, password reset invalidation, safe redirects, unavailable configuration, throttling, and no-cache responses. Eight existing backup tests also pass. These checks use temporary test data; validate the tunnel and browser behavior on the Pi after installation.

References: [Werkzeug password utilities](https://werkzeug.palletsprojects.com/en/stable/utils/) and [Flask configuration](https://flask.palletsprojects.com/en/stable/config/).
