# Nullbin

Private services you can host yourself, encrypted in the browser so the
server only ever stores data it cannot read. No accounts, no database.

- **Paste**: share text and files with a private link. The key is the part
  of the link after `#`, which browsers never send to the server.
  Passwords, file attachments, encrypted comments, expiry and burn after
  reading are built in.
- **Null Chat**: a temporary end-to-end encrypted group chat, kept only in
  the server's memory, that deletes itself.

## Start here

| I want to… | Go to |
|---|---|
| Learn how to use Nullbin | [Using Nullbin](#using-nullbin) |
| Try it on my own computer | [Try it locally](#try-it-locally) |
| Host it for others | [Choose a setup](#choose-a-setup), then [Option A](#option-a-one-server-recommended) or [Option B](#option-b-separate-hosting) |
| Update, check or manage my server | [Run your server](#run-your-server) |
| Fix a problem | [Troubleshooting](#troubleshooting) |
| Understand what is protected | [How your data is protected](#how-your-data-is-protected), then the full [threat model](THREAT_MODEL.md) |
| Review the Null Chat protocol | [ROOM_PROTOCOL.md](ROOM_PROTOCOL.md), with its [ProVerif model](proverif/) |
| Look up limits, settings, the API or the encryption | [Reference](#reference) |
| Report a security problem | [SECURITY.md](SECURITY.md): email hi@jacobzymet.com, never a public issue |
| Contribute or make a release | [CONTRIBUTING.md](CONTRIBUTING.md) |
| See the license | [AGPL-3.0](LICENSE), and [third-party notices](THIRD_PARTY_NOTICES) |

## Using Nullbin

Nullbin works in current Chrome, Edge, Firefox and Safari (browsers from
mid-2022 on; Safari 16.4 or later). Older browsers cannot open it.

1. Enter text, attach files, or both. Drop files on the page or paste an
   image (such as a screenshot) to attach it. Several files are sent as one
   zip archive, which the reader downloads and opens. Readers can view an
   attached PNG, JPEG, GIF or WebP image with **Show image**.
2. Choose how long the paste lasts, and any options: a password, a
   discussion, or burn after reading.
3. Select **Create** and share the **whole link, including everything after
   `#`**. It is copied for you when the browser allows; otherwise use
   **Copy link**.
4. If you set a password, send it separately from the link. Keep the
   **delete link** to yourself: anyone with it can delete the paste.

| Option | What it does |
|---|---|
| **Password** | Readers need the password as well as the link. At least 8 characters. The key button generates a strong random one (20 characters, about 116 bits) and shows it, so you can copy it and send it separately. |
| **Separate links** | One link for each person (2 to 20), instead of one shared link. Each link counts its own opens (with burn after reading, each gets that many), and the delete link shows how often each was opened and can revoke any of them. Revoking stops that link from opening the paste, but cannot take back what its holder already saw. Cannot be combined with a discussion. |
| **Discussion** | Everyone who can open the paste can read and post encrypted comments: with a password, only people who also know it. Cannot be combined with burn after reading. |
| **Burn after reading** | The paste is deleted after a set number of opens (1 to 1,000; 1 by default). Every authorized open counts, including reloads and interrupted downloads; wrong passwords and link previews do not. Leaving the page clears the paste from it, even while it is still opening, so **Back** does not bring it back. |

After opening a paste:

| Button | What it does |
|---|---|
| **New** | Starts a blank paste. |
| **Clone** | Copies the text and attachment into a new draft, where you choose new settings. Comments and the password are not copied. |
| **Raw text** | Opens the full text in a new tab as plain text. |
| **Save document** | Downloads the full text as `paste.txt`. Attachments have their own **Save file** button. |
| **Show preview** | Shows a text attachment (such as `.txt`, `.md`, `.json` or `.csv`) as plain text, only after you click. JSON and Markdown stay literal source text. Images use **Show image**. |
| **Email** | Opens your email app with the link. The text and password are not included and nothing is sent automatically. |
| **QR code** | Shows a QR code of the link, made in your browser. |

The paste page and the page you get after creating one show how long until
the paste is deleted, counting down. The time comes from the server.

Email and QR code contain the secret link, so send any password another
way. If a paste contains invisible or direction-changing characters (a trick
that makes text look different from what it does when copied), Nullbin shows
a warning above it.

### Null Chats

A Null Chat is a group chat that deletes itself. Choose **Null Chat** in
the menu at the top (or open `/chat`), enter your name, optionally a chat
name, and
choose:

- **Self-destructs after**: 5 minutes to 1 week.
- **People, you included**: 2 (a one-to-one chat) to 20. The server refuses
  invites past it, and everyone's app refuses to let in anyone past it, so
  a one-to-one chat stays one-to-one even if the server is tampered with.
  Invites that can still be used count, as do members; removed people,
  revoked and expired invites do not.
- **Password** (optional): joining also takes it, so a leaked invite link
  alone gets nobody in. Send it a different way from the links. It never
  leaves your browser: the tab keeps only a key derived from it (Argon2id).
  Each invite allows one try: a wrong password closes that invite.

Then **Create Null Chat**.

- **Invite** people one at a time: type who the invite is for, then copy the
  link and send it to that person. Choose how long the link works: 5
  minutes, 15 minutes (the default) or an hour. Each invite works once, and
  only for that long: once used, expired or revoked, the link opens nothing.
  The server refuses an expired invite, and your tab refuses a join it first
  sees more than ten minutes after the expiry, whatever the server does.
  **Revoke this invite** (in the invite window, or **Revoke invite** in
  Members) stops a link at once. Keep the room open
  while people join: your tab lets them in, and until it does they see a
  waiting screen with their safety code, without the chat or its controls.
  Pending visitors cannot self-destruct the room or send anything beyond
  their one join announcement. Each invite lets one person in. If your tab sees two people
  prove they had the same invite (only a tampered server allows it), it
  closes that place, even if one of them got in: send a new invite another
  way. It also tells you when someone's invite link was changed on the way.
- **Chat** as in any messaging app. Right-click a message (long-press on a
  phone, or use the ⋯ button beside it) to react with one of six emoji,
  reply, copy it, or edit or unsend your own; double-click to reply. Edited
  messages show "(edited)".
  Unsending removes a message from everyone's screen, but anyone may already
  have read or copied it. There are no typing indicators or read receipts
  on screen: both would tell the server who is active. (Each message does
  tell the other members, not the server, what its sender had read, so the
  room can warn when people were shown different things.)
- **Members** (the member count at the top) lists everyone with a code, and
  whose invite they used when their name differs from it. To be sure nobody
  is posing as someone, compare a person's code with the one they see, in
  person or on a call, then **Mark verified**: their name then shows a check
  mark, in this tab. Names that look like another one in the room get the
  start of their code as a badge. The creator can remove people there.
- **Warnings**: the room tells you if someone seems to be showing people
  different messages or keys, or leaving you out. Take them seriously:
  compare with the others another way, and leave if in doubt.
- **Self-destruct** (the flame at the top): anyone in the room can end it for
  everyone, at once, after confirming. Otherwise it self-destructs when its
  time is up.

Messages are end-to-end encrypted with forward secrecy: every message has its
own key, which is deleted once used, and keys change when someone is
removed. Names, the room's name and invite labels are encrypted too, so an
invite link alone shows none of them. Only people in the room can read it, not even the server, which
keeps rooms only in memory: a server restart also ends them. Your access
stays in the browser tab where you joined (one tab at a time); closing it
ends your access unless the browser restores the tab (ask for a new invite
to come back), and after a reload you see new messages only. New members
cannot read messages from before they joined. If the room ever shows that
someone else took your place, leave and tell the person who invited you.
Rooms are text only: up to 20 places (each invite uses one, even if it is
revoked, expires or the person is removed) and 1,000 records (messages,
reactions, edits and key changes all count). Keys take more of them the
more people join: a room of 5 keeps roughly 900 for messages, a full room
of 20 roughly 400 to 500.

### Large attachments

Desktop Chrome and Edge save attachments of any size directly
to disk. Other browsers can save attachments up to 64 MiB. Clone works for
attachments up to 64 MiB, or for larger ones after you save them.

Previews authenticate the complete attachment first. Text previews accept
UTF-8 files up to 1 MiB and display at most 5,000 lines or 100,000 characters.
Documents such as PDFs are not previewed, to keep document parsers out of the
page: save them and open them in your usual viewer. Previews do not make files
safe to open elsewhere.

## Try it locally

**You need** [Docker Desktop](https://docs.docker.com/get-started/get-docker/),
installed and running (on Windows, using **Linux containers**). You do not
need Node.js or Go. These commands work in Windows PowerShell, Linux and
macOS.

1. Download Nullbin:

   ```sh
   git clone https://github.com/jacobzymet/nullbin-go.git nullbin
   cd nullbin
   ```

   This is the development version, which is fine for trying it out. For
   the latest release, also run `git checkout --detach refs/tags/v1.2.3`
   with the version from the [Releases page](https://github.com/jacobzymet/nullbin-go/releases).

2. Build it. The first build takes a few minutes:

   ```sh
   docker build --build-arg VERSION=$(git describe --tags --always) -t nullbin-dev .
   ```

   The `VERSION` part puts the version at the bottom of every page. If you
   downloaded a ZIP instead of using Git, leave it out:
   `docker build -t nullbin-dev .`

3. Start it:

   ```sh
   docker run --rm --ulimit core=0 -p 127.0.0.1:8080:8080 -v nullbin-dev-data:/data nullbin-dev
   ```

4. Open [http://localhost:8080](http://localhost:8080) and create a paste.
   Press **Ctrl+C** in the terminal to stop it. Run the same `docker run`
   command to start it again; your pastes are kept.

This local copy is only reachable from your own computer. To host Nullbin
for others, with HTTPS, follow one of the setups below.

## Choose a setup

Nullbin has two parts: the **website** (the frontend, which encrypts and
decrypts in the browser) and the **API** (which stores encrypted pastes).

| Setup | Where the parts run | Choose it if |
|---|---|---|
| [**Option A: One server**](#option-a-one-server-recommended) (recommended) | Both on one server, in separate containers | You want the simplest setup. |
| [**Option B: Separate hosting**](#option-b-separate-hosting) | Website on a static host such as Cloudflare Pages; API on your server | You want the website to stay safe even if the API server is broken into. |

Both support every feature. Option A is easier. Option B is safer if the
server is ever compromised: the code that handles keys is not on it.

**What you need for either:**

- A server running **Ubuntu 24.04** with at least **1 GB of RAM** and SSH
  access.
- A **domain name** (such as `paste.example.com`) whose DNS points at that
  server.
- TCP ports **80 and 443** open in the server's firewall and in your
  hosting provider's firewall.
- Optional: **Cloudflare's proxy** in front of the server. See
  [Behind Cloudflare](#behind-cloudflare).

**Servers always run a published release**, never the development branch:
the install steps download the latest release, and Docker builds it on your
server from source. Nothing prebuilt is downloaded.

**Prefer no manual steps?** [cloud-init](#new-server-with-cloud-init) sets
up Option A automatically when you create the server.

## Option A: One server (recommended)

Replace `paste.example.com` with your domain throughout.

**1. Install Docker and download the latest release.** Connect to your
server with SSH and run:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 git curl
VERSION=$(curl -fsSL https://api.github.com/repos/jacobzymet/nullbin-go/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d '"' -f 4)
echo "Installing $VERSION"
git clone --no-checkout https://github.com/jacobzymet/nullbin-go.git nullbin &&
git -C nullbin checkout --detach "refs/tags/$VERSION" &&
cd nullbin/deploy
```

It should print a version such as `Installing v1.2.3`. If it prints only
`Installing`, stop: see [troubleshooting](#troubleshooting). A message about
a "detached HEAD" is normal.

**2. Set your domain.** Give the domain name only, without `https://`:

```bash
sudo ./nullbin setup paste.example.com
```

If Cloudflare's proxy (orange cloud) will be in front of the server, add
`--cloudflare` (or `--cloudflare-self-signed`) to that command and read
[Behind Cloudflare](#behind-cloudflare) first.

**3. Start Nullbin.** The first start takes a few minutes:

```bash
sudo ./nullbin start
```

**4. Check it.** Open `https://paste.example.com` and create a test paste.
The bottom of the page shows the version you installed. HTTPS certificates
are created and renewed automatically, and Nullbin starts again by itself
after the server reboots.

Done. To update and manage it, see [Run your server](#run-your-server).

## Option B: Separate hosting

You will use two addresses. Replace both with your own throughout:

| Address | What it is | Points at |
|---|---|---|
| `https://paste.example.com` | The website people open | Your static host |
| `https://api.example.com` | The API that stores encrypted pastes | Your server |

**1. Set up the API on your server.** Point `api.example.com` at the server,
connect with SSH and run:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 git curl
VERSION=$(curl -fsSL https://api.github.com/repos/jacobzymet/nullbin-go/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d '"' -f 4)
echo "Installing $VERSION"
git clone --no-checkout https://github.com/jacobzymet/nullbin-go.git nullbin &&
git -C nullbin checkout --detach "refs/tags/$VERSION" &&
cd nullbin/deploy
```

**Write down the version it prints** (such as `v1.2.3`); you will build the
website from the same one. If it prints only `Installing`, stop: see
[troubleshooting](#troubleshooting).

Configure the API with its domain name, then the website's exact address
(`https://` and no trailing slash), and start it:

```bash
sudo ./nullbin setup-api api.example.com https://paste.example.com
sudo ./nullbin start
```

Check: `https://api.example.com/api/v1/version` should show `"mode":"api"`
and your version. The API's home page showing "Not found" is expected.

**2. Build the website on your own computer.** Use the version you wrote
down:

```sh
git clone --no-checkout https://github.com/jacobzymet/nullbin-go.git nullbin
git -C nullbin checkout --detach refs/tags/v1.2.3
cd nullbin
```

Then build it with your API's address and the website's own address (the
second one only gives link previews in chat apps their image), using
**one** of these:

- **With Docker** (works in PowerShell, Linux and macOS). The output folder
  is `out/frontend`:

  ```sh
  docker build --target frontend-files --build-arg API_ORIGIN=https://api.example.com --build-arg SITE_ORIGIN=https://paste.example.com --build-arg VERSION=$(git describe --tags) --output type=local,dest=out/frontend .
  ```

- **With Node.js 26 or later.** The output folder is `web/dist`:

  ```sh
  npm ci --ignore-scripts
  ```

  Then on Linux or macOS:

  ```bash
  NULLBIN_API_ORIGIN=https://api.example.com NULLBIN_SITE_ORIGIN=https://paste.example.com npm run build:frontend
  ```

  Or in Windows PowerShell:

  ```powershell
  $env:NULLBIN_API_ORIGIN = "https://api.example.com"
  $env:NULLBIN_SITE_ORIGIN = "https://paste.example.com"
  npm run build:frontend
  ```

**3. Upload the website.** Use a static host that supports `_headers` and
`_redirects` files, such as Cloudflare Pages. These apply the security
headers and make paste links work. For Cloudflare Pages:

1. Create a Pages project using **Direct Upload**.
2. Upload the **whole** output folder (`out/frontend` or `web/dist`),
   including `_headers` and `_redirects`.
3. Under **Custom domains**, add `paste.example.com` and follow the DNS
   instructions.

**4. Check it.** Open `https://paste.example.com`, create a paste and open
its link.

The website's address must **exactly** match the one you gave `setup-api`.
Preview addresses from your host are not allowed. To use your host's own
address instead (such as `https://your-project.pages.dev`), give that to
`setup-api`.

Done. To update and manage it, see [Run your server](#run-your-server).

## Run your server

Everything here runs **on the server, in the `nullbin/deploy` folder**
(`/opt/nullbin/deploy` on a cloud-init server), and works the same for
Option A and Option B.

### Everyday commands

| Task | Command |
|---|---|
| Update to the latest release | `sudo ./nullbin update` |
| Show the running version and container status | `sudo ./nullbin status` |
| Show how many pastes there are, and storage and disk space used | `sudo ./nullbin stats` |
| Read recent logs | `sudo ./nullbin logs` |
| Stop | `sudo ./nullbin stop` |
| Start | `sudo ./nullbin start` |
| Remove a reported paste | `sudo ./nullbin delete <paste id>` |
| Turn Cloudflare mode on or off | `sudo ./nullbin cloudflare on` (or `self-signed`, or `off`) |
| Show Cloudflare mode, the certificate and the SSL setting to use | `sudo ./nullbin cloudflare` |
| Free disk space used by old builds | `sudo ./nullbin cleanup` |
| List every command | `./nullbin help` |

None of these delete pastes, except `delete` for the one paste you name.

### Update

**Update notices are on by default** on systemd Linux servers. After a
successful `sudo ./nullbin start` or update, the server checks GitHub's
latest stable release every hour (spread over the first five minutes of
the hour). If it is newer than the installed version, a notice appears
when you next log in by SSH or at the console. Updates are never installed
automatically. Install security fixes promptly.

The checker runs as a dedicated unprivileged user, outside the containers,
and sends no paste data or local version to GitHub. Login reads a cached
result, so an unavailable GitHub never delays login; a failed check keeps
the last successful result. The installed version is refreshed after each
successful start. Development builds do not show release notices.

Ubuntu/Debian use the login MOTD; on other hosts the notice uses
`/etc/profile.d` and needs a shell that reads it. Hosts without systemd
skip these notices. You can also choose **Watch → Custom → Releases** on
the [repository](https://github.com/jacobzymet/nullbin-go).

To check immediately, run
`sudo systemctl start nullbin-update-check.service`. To turn off hourly
checks, run `sudo systemctl disable --now nullbin-update-check.timer`;
restarts and upgrades respect this choice. Turn them back on with
`sudo systemctl enable --now nullbin-update-check.timer`. Diagnostics are
in `journalctl -u nullbin-update-check.service`. Disabling checks leaves
the last cached result available at login.

1. Read the release's notes on the
   [Releases page](https://github.com/jacobzymet/nullbin-go/releases). They
   say if an update needs anything extra.
2. Connect to the server with SSH and run:

   ```bash
   cd ~/nullbin/deploy
   sudo ./nullbin update
   ```

   It shows the installed and the new version, switches to the new release,
   rebuilds, and waits until Nullbin is running. Your settings and pastes
   are kept; the site is down for a few seconds. If the new version does
   not start, it goes back to the one you had and says so.
3. Open your site and create a test paste.

**Option B:** after updating the server, build the website from the same
version and upload it again (steps 2 and 3 of
[Option B](#option-b-separate-hosting)). In your existing copy on your
computer, switch versions with `git fetch --tags` and
`git checkout --detach refs/tags/v1.2.3`.
Always update the server first.

`update` installs only versions published on the Releases page from the
main branch, and refuses if files in `~/nullbin` were changed or added
(other than your settings), because they would be built in.

**To go back to an earlier release**, give its version:
`sudo ./nullbin update v1.2.2`. Check that release's notes first; a release
that changes how pastes are stored will say whether going back is safe.

### Remove a reported paste

A report usually includes a link such as
`https://paste.example.com/p/0123456789abcdef0123456789abcdef#…`. You need
only the 32 characters after `/p/` (or `/d/`), not the part after `#`:

```bash
sudo ./nullbin delete 0123456789abcdef0123456789abcdef
```

It prints `Deleted.`, and the paste and its comments are gone. The API is
offline for a few seconds while it runs.

### Change settings

The settings are in `deploy/.env` (Option A) or `deploy/.env.api`
(Option B). Edit the file, for example with `nano .env`, then apply the
change with `sudo ./nullbin start`.

| Setting | Default | What it controls |
|---|---|---|
| `MAX_SIZE` | `100MiB` | Largest paste, including its attachment. Up to `2GiB`. |
| `MAX_STORAGE` | `10GiB` | Total space Nullbin may use. Keep it well below the disk's free space. |
| `MAX_PENDING` | `1024` | How many uploads can be in progress at once. |
| `MAX_PASTES` | `100000` | Most pastes kept at once. Each uses about four inodes; check with `df -i` before raising it. |
| `DOMAIN` (A) or `API_DOMAIN` (B) | set by `setup` | The server's domain name. |
| `FRONTEND_ORIGIN` (B only) | set by `setup-api` | The website's exact address. |
| `ROOMS` | `true` | `false` turns Null Chats off. |
| `CLOUDFLARE` | not set (off) | `true` when Cloudflare's proxy is in front, `self-signed` to also never use Let's Encrypt. Change it with `sudo ./nullbin cloudflare on`, `self-signed` or `off`, not by hand. See [Behind Cloudflare](#behind-cloudflare). |

Write each setting on its own line as `NAME=value`, with no quotes or
spaces. `./nullbin` refuses to start with anything else (other forms that
Docker Compose would accept, unknown names, a name set twice, or Windows line
endings), because the domain names end up in the HTTPS proxy's
configuration.

If you change the **API's address** in Option B, also rebuild and upload
the website with the new address. If you change the **website's address**,
existing share links keep pointing at the old one.

### Behind Cloudflare

Use Cloudflare mode when Cloudflare's proxy (the orange cloud) is in front
of your server, in Option A or Option B.

**1. Turn it on**, on the server:

```bash
sudo ./nullbin cloudflare on
```

(Or add `--cloudflare` to `setup` or `setup-api` when you first set up.)
`sudo ./nullbin cloudflare off` turns it off again.

**Don't want Let's Encrypt at all?** Use
`sudo ./nullbin cloudflare self-signed` (or `--cloudflare-self-signed`)
instead. The server then always uses its own certificate and never contacts
Let's Encrypt, so it needs only port 443 open to Cloudflare, and Cloudflare
must stay on **Full**. Everything else is the same as `on`.

**2. In Cloudflare's dashboard:**

- **DNS:** the record for your domain points at the server and is
  **Proxied** (orange cloud).
- **SSL/TLS → Overview:** run `sudo ./nullbin cloudflare`. It says which
  mode to use:
  - **Full (strict)** once the server has a Let's Encrypt certificate. This
    is the one to aim for: Cloudflare then checks that it is really talking
    to your server.
  - **Full** while the server uses its own certificate (see below). It is
    encrypted, but Cloudflare does not check who answers.
  - Never **Flexible**: it would send everything unencrypted between
    Cloudflare and your server.
- **Turn off features that rewrite pages:** Rocket Loader, Email Address
  Obfuscation and automatic Web Analytics injection. Nullbin's security
  checks block such changes, so they would break the page.

**What Cloudflare mode does:**

- **Only Cloudflare can reach the site.** Any other connection gets
  `403 This site is served only through Cloudflare.`. This is enforced by
  Nullbin's own proxy, so it holds even though Docker's published ports skip
  host firewalls such as ufw. Keep **port 80 open to Cloudflare**: Let's
  Encrypt checks your domain through it.
- **Each visitor keeps their own rate limits.** Behind Cloudflare, every
  connection comes from Cloudflare's addresses. Nullbin uses the visitor's
  address that Cloudflare reports in `CF-Connecting-IP`, and believes that
  header only on connections from Cloudflare's published addresses
  ([list](https://www.cloudflare.com/ips/)). Nobody else can fake it.
- **Certificates:** the server asks Let's Encrypt for a certificate first.
  If that fails, it uses a certificate from its own local authority right
  away, so the site works with Cloudflare's **Full** mode. It tries Let's
  Encrypt again about every 40 minutes and switches over once it succeeds.
  Visitors only ever see Cloudflare's certificate.

**What Cloudflare can see:** Cloudflare decrypts the traffic between
visitors and your server. It sees visitors' addresses, paste IDs, access
tokens and encrypted pastes, but never paste contents, passwords or keys:
those stay in the browser, and the key is never sent over the network. In
Option A, Cloudflare also delivers the website's code, so you trust it as
much as your own server not to change that code. In Option B, with only the
API behind Cloudflare, it never delivers code.

Cloudflare's address list is built into Nullbin and checked against
Cloudflare's published one on every change. If Cloudflare adds addresses,
a Nullbin update brings them; until then, visitors routed through the new
addresses are refused rather than trusted.

### Before you go public

1. **Keep it updated.** Watch for releases (see [Update](#update)).
   cloud-init servers install Ubuntu updates automatically; on other
   servers, turn on `unattended-upgrades`.
2. **Protect the accounts that control it.** Use SSH keys, not passwords,
   for the server. Keep the `nullbin` folder owned and writable by you
   alone: whoever can change it controls what runs as root, as with any
   Docker setup. Turn on two-factor authentication for the GitHub account
   that publishes releases. For Option B, protect the static host account
   too: it controls the code that handles keys.
3. **Publish a way to report abuse**, such as an email address on your
   domain. You cannot see what pastes contain, so reports are how you hear
   about illegal content. The **Report a vulnerability** link at the bottom
   of every page goes to the Nullbin maintainer and is only for security
   flaws in the software, not for reporting pastes.
4. **Check the live site from outside** with the
   [SSL Labs server test](https://www.ssllabs.com/ssltest/) and
   [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/observatory).
   Both should give top grades; look into any warning.
5. **Consider HSTS preloading.** Nullbin sends
   `Strict-Transport-Security`, but a browser learns it only on its first
   HTTPS visit, so a first visit typed as `http://` on a hostile network
   can still be intercepted. If every name under your domain serves
   HTTPS, send `max-age=63072000; includeSubDomains; preload` from the
   domain itself and submit it at [hstspreload.org](https://hstspreload.org/).
   This affects every subdomain, so it is your decision, not a default.

The API's request and bandwidth limits cover encrypted transfers. Website
files are served separately by Caddy (Option A) or your static host (Option
B), so any additional limits for that traffic belong at the proxy, CDN or
hosting provider.

### What the server knows

The server stores only encrypted pastes and what it needs to serve them:
size, creation and expiry times, burn and discussion settings, and hashes of
access tokens. The size is padded before encryption: every paste whose
encoded content fits in 16 KiB (up to about 16,000 characters of plain
English text; fewer with many line breaks, quotes or non-Latin characters,
which take more than one byte each) is the
same size, and larger ones are rounded up, so the size shows only a rough
range. Comments are padded the same way: all but the longest take the same
4 KiB. It does not log IP addresses, paste IDs or tokens, and keeps
nothing linking a paste to who uploaded it. So you cannot read a reported
paste, and you have no uploader details to hand over. Expired and deleted
pastes are removed from disk within a minute, but backups and disk
snapshots may keep copies.

### Data and backups

- Pastes are in the `nullbin_nullbin-data` Docker volume; HTTPS certificates
  are in `proxy-data` and `proxy-config`. Updates and `stop` keep them.
- The only thing that deletes all pastes is `docker compose down -v`, which
  removes the volumes. `nullbin` never does this.
- Run **one** API on **local disk**. Several API processes, or network file
  systems, are not supported.
- To switch between Option A and B on the same server, run
  `sudo ./nullbin stop`, delete the old settings file (`.env` or
  `.env.api`), run `setup` or `setup-api`, then `start`. Pastes are kept. Keep
  the same website address if existing links should keep working.

## Troubleshooting

| Problem | What to do |
|---|---|
| The install prints only `Installing`, or `nullbin update` cannot find the latest release | The server could not reach GitHub, or no release exists yet. Check the [Releases page](https://github.com/jacobzymet/nullbin-go/releases) and try again. Do not continue without a version. |
| The site does not open, or HTTPS is not ready | Check that DNS points at the right server and ports 80 and 443 are open in both firewalls. Then check `sudo ./nullbin status` and `sudo ./nullbin logs`. |
| The site says "This site is served only through Cloudflare." | Cloudflare mode is on, but visitors reach the server directly. Set the DNS record to **Proxied** in Cloudflare, or turn the mode off with `sudo ./nullbin cloudflare off`. |
| Cloudflare shows error 526 (invalid SSL certificate) | The server is using its own certificate while Cloudflare is set to **Full (strict)**. Run `sudo ./nullbin cloudflare` and set the mode it shows. |
| Cloudflare shows error 521 or 522 | Cloudflare cannot connect to the server. Check that ports 80 and 443 are open to Cloudflare in your hosting provider's firewall, and `sudo ./nullbin status`. |
| Option B: the API's home page shows "Not found" | That is expected. Check `https://api.example.com/api/v1/version` instead. |
| Option B: the website opens, but creating or opening pastes fails | The website's address must exactly match the one given to `setup-api`, and the website must be built with the API's address. Fix whichever is wrong, then rebuild or restart. |
| A share link opens the host's "page not found" | Upload the whole output folder, including `_redirects`. |
| `nullbin` says to run it with sudo | Run `sudo ./nullbin …` from the `deploy` folder. |
| `nullbin update` says files that came with Nullbin were edited | A file such as a Caddyfile was changed by hand, and updating would overwrite it. `git -C ~/nullbin stash` sets the changes aside so the update can continue. Your settings file is never affected. |
| `nullbin setup` says it is already configured | Edit the existing settings file instead (see [Change settings](#change-settings)), or delete it to start over. |
| The server is running out of disk space | Run `sudo ./nullbin cleanup`. It never deletes pastes. |

## How your data is protected

**In the browser.** Encryption, decryption, passwords and comments are all
handled in the browser. The server only ever receives encrypted data and
the access tokens it needs; it enforces expiry, burn after reading and
limits.

**The whole link is a secret.** Anyone with the full link can read the
paste, and also needs the password if one is set. Send the two separately.
Links can linger in browser history, chat logs and clipboard history.

**What you still have to trust:**

- **Whoever controls the website's code** (the server in Option A, or the
  static host in Option B) could change it to steal keys. Protect those
  accounts and keep the code updated.
- **The API** could delete or withhold pastes, keep encrypted copies, and
  see metadata such as padded sizes and times. It cannot read them.
- **Your own device:** malware or a malicious browser extension can read
  anything you see.

**Downloads and burning.** An interrupted burn download still uses an open.
Once the last open is used, the paste is gone for good.

For the full analysis, see the [threat model](THREAT_MODEL.md).

## Reference

<details>
<summary><strong>Technical specifications</strong>: architecture, encryption, keys and content limits</summary>

### Architecture

| Component | Specification |
|---|---|
| Frontend | TypeScript with native browser APIs; Bootstrap 5.3.8 CSS, without Bootstrap JavaScript or a framework. Builds to static HTML, JavaScript and CSS. |
| Cryptography | `libsodium-wrappers-sumo` 0.8.4 with bundled WebAssembly, running in the browser. No CDN or outside service. |
| Backend | Go 1.25 or later, standard library only: no third-party Go modules, database or accounts. |
| Storage | Ciphertext and JSON metadata on local disk. One API process per data directory. Files use mode `0600`, directories `0700`. |
| Deployment | The API and the Caddy HTTPS proxy run from distroless images (no shell, tools or package manager) as non-root users, with read-only root filesystems, no added capabilities and process limits; only their data volumes are writable. The API has no internet access. Caddy serves HTTP/1.1 and HTTP/2, without HTTP/3. Linux is the supported production platform. |
| Browser | JavaScript and WebAssembly; HTTPS in production. Clipboard access and streaming file saves are optional. |
| HTTP security | Strict Content Security Policy with Trusted Types (the browser refuses HTML-injection APIs), Subresource Integrity, `no-referrer`, `nosniff`, COOP and CORP `same-origin`, and COEP `require-corp` (isolating the page from side-channel memory reads). The API's CORS allows only the configured website, without cookies or credentials. |
| Distribution | Pinned dependencies, reproducible builds, and a checksum list with each release. Nothing prebuilt is published. See **Verify a build** below and the [third-party notices](THIRD_PARTY_NOTICES). |

### Encryption and keys

Pastes use **XChaCha20-Poly1305 with 256-bit keys**, through libsodium's
[`crypto_secretstream_xchacha20poly1305`](https://doc.libsodium.org/secret-key_cryptography/secretstream).
It encrypts files in small chunks and detects altered, missing, duplicated,
reordered or truncated data, without holding whole files in memory.

| Property | Specification |
|---|---|
| Link secret | 32 fresh random bytes per paste, written as 43 base64url characters after `#`. |
| Encryption key | A 32-byte stream key derived from the master key: the link secret alone, or the link secret combined with the password. |
| Password | Argon2id v1.3 with a fresh 16-byte salt, `opslimit = 3`, `memlimit = 256 MiB` and a 32-byte result, after Unicode NFC normalization. Keyed BLAKE2b-256 combines it with the link secret. Neither the password nor the master key is sent to the API. |
| Separate keys | Paste encryption, comment encryption, discussion access, burn access and separate-link access use distinct `crypto_kdf_derive_from_key` contexts. Access tokens sent to the server cannot decrypt anything. |
| Comments | XChaCha20-Poly1305 with a fresh 24-byte random nonce, under the separate comment key, bound to the paste ID. Names, text, times and replies are encrypted, and padded to 4 KiB (rounded up like pastes beyond that), so a comment's size does not show its length. Names are not verified. |
| IDs and tokens | Paste IDs are 128 random bits (32 hexadecimal characters); upload and delete tokens are 256 random bits. The server stores SHA-256 hashes of tokens and compares them in constant time. |

The part of the link before `#` finds the paste; browsers never send the
part after it. Nullbin reads the key, then removes it from the address bar.
The website's code must still be trusted: malicious code could read the key
or the text.

### Content limits

Binary units are powers of 1,024. Text limits count JavaScript UTF-16 units.

| Item | Limit |
|---|---|
| Paste size | 100 MiB by default; configurable from 64 KiB to 2 GiB, including encryption overhead and size padding. Every paste takes at least about 16 KiB; above that the two add at most 6.7%, and 3.3% above 64 KiB, so with the default limit the largest attachment is about 98 MiB. |
| Text and metadata | The encrypted metadata, including the text, filename and type, must fit in 16 MiB. |
| Attachments | Up to 100 files per paste, with optional text. Several files become one uncompressed zip archive in the sender's browser before encryption: names are stripped of folders, drive letters, control and direction characters and leading dots, and made unique; entries carry no real dates and are never executable. Filename and type up to 255 characters each. |
| Text preview | Up to 5,000 lines or 100,000 characters. Copy, Raw text, Save document and Clone use the full text. |
| Saving and cloning files | Up to 64 MiB in memory. Larger files need streaming saves (desktop Chrome or Edge). Files are never opened; images and plain text can be previewed only when the reader asks (**Show image**, **Show preview**), and archives never are. |
| Discussions | Up to 200 comments per paste; 4,000 characters of text and a 40-character name each. |
| Expiry | 5 or 30 minutes; 1, 3 or 12 hours; 1 or 3 days; 7 days or 30 days. Never unlimited. Expired pastes are never served and are removed within a minute. |
| Burn after reading | 1 to 1,000 authorized opens (default 1), counted before delivery and kept across restarts. |
| Separate links | 2 to 20 per paste, each with no open limit or 1 to 1,000 opens. |

<details>
<summary>Key derivation and data formats</summary>

Without a password, `master = link_secret`. With a password:

```text
stretched = Argon2id-v1.3(NFC(password), salt,
                        output=32 bytes, opslimit=3, memlimit=256 MiB)
master    = BLAKE2b-256(key=link_secret, message=stretched)
```

Each subkey is `crypto_kdf_derive_from_key(32, 1, context, master)`:

| Context | Purpose |
|---|---|
| `nbstream` | Paste and file encryption key |
| `nbcmtenc` | Comment encryption key |
| `nbcmtacc` | Discussion access token |
| `nbburnac` | Burn-read access token |
| `nbrcptac` | Key for the access tokens of separate links (never sent) |

The salt is public: random with a password, all zeros without. Access tokens
are base64url encoded; the server stores only their hashes.

**Separate links:** each link carries its own 16 random bytes after the key,
and its access token is `BLAKE2b-256(key = nbrcptac subkey, message = those
bytes)`. Making a token takes the link and any password, and someone who knows
the key but not another link's bytes cannot make that link's token, so a
revoked link cannot borrow another one.

**Encrypted paste, version 2** (written by this version):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 bytes | Magic `NBN1` |
| 4 | 1 byte | Version `2` |
| 5 | 1 byte | Flags: bit 0 means password protected; other bits must be zero |
| 6 | 16 bytes | Password salt |
| 22 | 24 bytes | libsodium secretstream header |
| 46 | rest | Encrypted frames |

Each frame is a 4-byte big-endian ciphertext length, then the ciphertext
(17 bytes of overhead). The first frame also authenticates bytes 0 to 21.
Together the frames carry one padded stream:

```text
4-byte big-endian JSON length || UTF-8 JSON || file bytes || zero bytes
```

The JSON has exactly `type`, `text`, `filename`, `mime`, `size` and
`discussion`. For `n` bytes of length, JSON and file, the stream is
`padded(n)` bytes long: 16 KiB for anything up to 16 KiB, and above that
the [Padmé](https://arxiv.org/abs/1806.03160) function, which rounds `n`
up so that only its top `floor(log2(floor(log2 n))) + 2` bits can be
non-zero. That leaves O(log log n) bits of size information: there are 371
possible padded lengths up to 100 MiB, about 8.5 bits. Every frame but the
last holds exactly 64 KiB of the stream; the last holds the rest and
carries `TAG_FINAL`. The total size is 46 bytes, plus the padded length,
plus 21 bytes per frame, so it depends only on the padded length: text and
file pastes of the same padded length have the same size and layout.
Readers reject any other padded length, non-zero padding, short or empty
frames, trailing bytes and incomplete streams. The viewer downloads and
verifies a paste of up to 64 MiB completely before showing it, so the
download looks the same whether or not a file is attached and whether or
not it is saved. It decides by the size implied by the authenticated
metadata, never by a header the server sends. A larger paste (always one
with a file) is read as the file is saved, so the server can see when the
reader stops after the text.

**Encrypted paste, version 1** (read only, so links from older versions
keep working until they expire): the same header with version `1`. The
first frame holds just the JSON. A text-only paste ends there with
`TAG_FINAL`; otherwise file frames of 64 KiB follow, the last carrying
`TAG_FINAL` (even for an empty file). There is no padding: the total size
is 46 bytes, plus 21 and the JSON size, plus the file size and 21 bytes per
file frame. Changing the version byte makes the first frame fail to
authenticate.

**Encrypted comment, version 2:** a version byte (`2`), a 24-byte nonce,
then XChaCha20-Poly1305 ciphertext with a 16-byte tag. The plaintext is the
length of the JSON (4 bytes, big-endian), UTF-8 JSON with `id`, `parent`,
`name`, `text` and `time` (milliseconds), then zeros up to `padded(n)` for
`n` = 4 + the JSON length, with a 4 KiB minimum instead of 16 KiB. Every
comment whose JSON fits in 4,092 bytes (about 3,900 characters of plain
English text) is stored as 4,137 bytes; the longest possible one is about
24 KiB. The additional authenticated data is
`nullbin comment v2 <paste id>`, so the version cannot be changed. Readers
reject any other padded length and non-zero padding.

**Encrypted comment, version 1** (written before comment padding, still
read): the same without the length and padding: the plaintext is just the
JSON, and the additional authenticated data is
`nullbin comment v1 <paste id>`.

Code: [paste crypto](web/src/crypto.ts), [format](web/src/format.ts),
[comments](web/src/comments.ts), [links](web/src/link.ts).

</details>

</details>

<details>
<summary><strong>Server configuration</strong>: environment variables, rate limits and transfer limits</summary>

The settings files set these environment variables for the API. Bad values,
and unknown `NULLBIN_*` variables (usually typos), stop the server at
startup.

| Variable | Default | Meaning |
|---|---|---|
| `NULLBIN_API_ONLY` | `false` (`true` in the API image) | Serve only the API, no website. |
| `NULLBIN_FRONTEND_ORIGIN` | empty | The exact HTTPS website address allowed to call the API. |
| `NULLBIN_LISTEN_ADDR` | `127.0.0.1:8080` (`:8080` in the image) | Address and port to listen on. |
| `NULLBIN_DATA_DIR` | `data` (`/data` in the image) | Data directory, created with mode `0700`. |
| `NULLBIN_MAX_STORAGE` | `10GiB` | Total storage budget, from `64KiB` up to `1048576GiB` (1 PiB), including unfinished uploads, metadata and comments. Units: `KiB`, `MiB`, `GiB`. |
| `NULLBIN_MAX_PENDING` | `1024` | Unfinished uploads at once (1 to 4096). |
| `NULLBIN_MAX_PASTES` | `100000` | Pastes at once, including unfinished ones (1 to 10,000,000). Keeps a volume from running out of inodes before bytes. |
| `NULLBIN_MAX_SIZE` | `100MiB` | Largest paste, `64KiB` to `2GiB`. |
| `NULLBIN_BEHIND_HTTPS` | `false` | `true` sends `Strict-Transport-Security: max-age=31536000`. |
| `NULLBIN_TRUSTED_PROXIES` | empty | IPs or CIDR ranges whose `X-Forwarded-For` header is trusted. Public ranges wider than /12 (IPv4) or /29 (IPv6) are refused; private, shared and loopback ranges may be wider (such as 10.0.0.0/8 or fc00::/7). |
| `NULLBIN_ROOMS` | `true` | Null Chats. `false` removes their API: a separately hosted website's room page then says rooms are off, and the all-in-one server answers room links with 404. They are kept in memory only: at most 1,000 rooms and 128 MiB in total; 4 MiB of messages per room; and per client network (IPv4 address or IPv6 /64) at most 10 live rooms holding 4 MiB of messages together, four times that per IPv6 /48. |

The `nullbin` program also has `nullbin healthcheck` (used by the container
health check) and `nullbin delete <paste id>` (used by `./nullbin delete`;
the server must be stopped).

**Request rates per client** (IPv4 address or IPv6 `/64`):

| Requests | Sustained | Burst |
|---|---|---|
| Create a paste | 20 per minute | 20 |
| Upload chunks and finalize | 10 per second | 50 |
| Post comments | 20 per minute | 10 |
| Delete a paste | 60 per minute | 20 |
| Downloads, burn reads and comment reads (shared) | 20 per minute | 20 |
| Pages, assets and the version link | 5 per second | 100 |
| Create a Null Chat | 10 per minute | 10 |
| Null Chat messages, invites, joins and creator actions | 2 per second | 30 |
| Null Chat reads (polling) | 10 per second | 100 |

One IPv6 `/48` as a whole gets four times a client's rates and bursts.
Each limiter tracks up to 100,000 clients and refuses new ones when full.
Forwarded addresses are trusted only from `NULLBIN_TRUSTED_PROXIES`.

**Transfer and timeout limits:**

| Limit | Value |
|---|---|
| Unfinished upload lifetime | 2 minutes without a completed chunk; 1 hour at most |
| Unfinished uploads | `MAX_PENDING` in total; 8 per client and 32 per IPv6 `/48` |
| Upload chunk size | 4 MiB to 8 MiB, except the last chunk |
| Concurrent chunk uploads | 512 in total; 4 per client and 16 per IPv6 `/48` |
| Minimum upload rate | 16 KiB/s on average after 5 seconds |
| Concurrent downloads | 512 in total; 16 per client and 32 per IPv6 `/48` |
| Minimum download rate | 32 KiB/s on average after 2 minutes (for password and save dialogs). Time the server spends on its own bandwidth limits does not count. Every download also ends 1 minute plus 1 second per 32 KiB of paste after it starts. |
| Download bandwidth | 4 MiB/s per client, 16 MiB/s in total |
| Request size | 4 KiB to create a paste; 16 KiB of headers |
| Disk writes at once | 64 creates, finalizes, deletes and comments; others wait up to 10 s |
| Timeouts | 10 s for headers, 60 s idle, 30 s for other requests, 5 minutes per upload chunk |

An upload is charged 32 KiB when it starts and its bytes as they arrive,
so uploads that send nothing cannot fill the budget. It starts only if the
whole paste fits at that moment, but other uploads can take the space
before it finishes. Each comment is charged when it is posted, so an
unused discussion costs nothing. A full budget returns `507`; too
many uploads or transfers return `503` with `Retry-After`. This is
Nullbin's own budget, not a disk quota: leave free disk space, or use a
dedicated volume.

</details>

<details>
<summary><strong>API reference</strong>: endpoints, tokens, responses and link formats</summary>

All endpoints are under `/api/v1`. Errors are JSON: `{"error": "..."}`.
Every response carries the security headers. Unknown, expired and burned
pastes, and wrong tokens, all return the same `404`.

**`POST /api/v1/pastes`** starts an upload (`Content-Type: application/json`;
rate limited):

```json
{"expires_in": 86400, "burn_after_reading": false, "total_size": 12345}
```

- `expires_in`: seconds; one of `300`, `1800`, `3600`, `10800`, `43200`, `86400`, `259200`, `604800`, `2592000`.
- `total_size`: the exact ciphertext size, from 67 bytes to the maximum.
- `max_reads` (optional, burn only): 1 to 1000, default 1.
- `comment_token` (optional, not with burn): 43 base64url characters;
  enables a discussion.
- `burn_token` (required for burn, otherwise not allowed): 43 base64url
  characters, derived in the browser with the `nbburnac` context.
- `recipients` (optional): separate links, 2 to 20 entries of
  `{"token": "<43 base64url characters>", "max_reads": n}`, where `max_reads`
  (1 to 1000) is optional and its absence means no limit. Requires
  `"burn_after_reading": true` and replaces `burn_token`, `max_reads` and
  `comment_token`, which are then not allowed. Tokens must differ.

Returns `201` with `{"id": "...", "upload_token": "...", "delete_token": "..."}`;
or `400` invalid, `413` too large (with `max_size`), `415` wrong type, `429`
rate limited, `503` too many uploads in progress, `507` storage full.

**`PUT /api/v1/pastes/{id}/chunks/{n}`** uploads chunk `n` (0, 1, 2, … in
order; `application/octet-stream`) with `Nullbin-Upload-Token`. Each chunk is
4 MiB to 8 MiB, except the last. A failed chunk may be sent again with the
same `n`. An upload expires after 2 minutes without a completed chunk, and
after 1 hour at most. Returns `204`; or `400` bad index, empty or too-small
chunk, `404`, `409` out of order (with `next_chunk`) or busy, `413` too
large, `415` wrong type.

**`POST /api/v1/pastes/{id}/finalize`** (with `Nullbin-Upload-Token`)
publishes the paste once all bytes have arrived. Returns `200` with
`{"expires_at": "..."}`; or `400` incomplete, `404`.

**`GET /api/v1/pastes/{id}`** streams a normal paste's ciphertext. Burn
pastes return `404`. `HEAD` returns `405`.

**`GET /api/v1/pastes/{id}/prefix`** returns a burn paste's first 22 bytes
(format, flags and password salt), without using an open. It answers `200`
for any live burn paste (its ID is enough) and `404` otherwise.

**`POST /api/v1/pastes/{id}/read`** (with `Nullbin-Burn-Token`) streams a
burn paste, using one open before any data is sent. A wrong or missing
token returns `404` and uses nothing. The response includes
`Nullbin-Reads-Remaining`. For a paste with separate links, the token is
one link's own: the open counts against that link only, the count is that
link's (and is left out when it has no limit), and a link that was revoked or
has used all its opens returns `410` to its own token.

Every download also includes `Nullbin-Expires-In`: the seconds until the
paste expires.

**`DELETE /api/v1/pastes/{id}`** (with `Nullbin-Delete-Token`) deletes the
paste and its comments. Returns `204`; or `404`, `409` busy.

**`GET /api/v1/pastes/{id}/recipients`** (with `Nullbin-Delete-Token`)
returns each separate link, in order:
`{"recipients": [{"opens": 1, "max_opens": 2, "revoked": false}, ...]}`
(`max_opens` is `null` for no limit, and such a link's `opens` stops counting at 1000). Other pastes return `404`.

**`POST /api/v1/pastes/{id}/recipients/{n}/revoke`** (with
`Nullbin-Delete-Token`) closes link `n` (from 0) for good. Once every link is
revoked or used up, the paste is deleted. Returns `204`; or `404`, `409` busy.

**`POST /api/v1/pastes/{id}/comments`** (with `Nullbin-Comment-Token`) adds
one encrypted comment of 41 bytes to 32 KiB. Returns `201` with
`{"count": n}`; or `400`, `404`, `409` full or busy, `413`, `415`.

**`GET /api/v1/pastes/{id}/comments`** (with `Nullbin-Comment-Token`)
returns `{"comments": ["<base64>", ...]}` in arrival order, streamed;
clients must require a complete JSON document.

**`GET /api/v1/version`** returns `{"version":"v1.2.3","mode":"api"}` from the
API. The local all-in-one server also returns its website files' hashes. A
separately hosted website lists its version and hashes at `/version.json`.

**Links** always use the website's address: `https://host/p/<id>#<key>`
(with `.b` after the key for burn after reading), and
`https://host/d/<id>#d.<delete token>`. A separate link adds `.r` and its 22
base64url characters after the key (and after any `.b`); the delete link of
such a paste ends in `.r`, so its page lists the links.

**Separate website (Option B):** the API's `NULLBIN_FRONTEND_ORIGIN` and the
website's build-time `NULLBIN_API_ORIGIN` name each other. CORS allows only
that exact website, never with cookies or credentials, and tokens are still
required for every change.

</details>

<details>
<summary><strong>Null Chats</strong>: keys, forward secrecy, formats and endpoints</summary>

**Keys.** A room key (32 random bytes) travels only in invite links, after
the `#`. It encrypts *control records*: joins, admits, the room name, invite labels,
removals and key deliveries (`crypto_kdf` context `nbroomen`,
XChaCha20-Poly1305, additional data `nullbin room v1 <room> <slot>`). Names,
the room's name and labels inside them are encrypted again, padded to 160
bytes, under a *roster key* that only members get: the creator makes it, and
seals it to each member in the `admit` that lets them in (with their name,
encrypted under it). A joiner's join carries its name sealed to the
creator's *name key* (an X25519 key in the creator's join), so only the
creator reads it before letting them in. So the room key, which every
invite link carries, shows who is in the room only as places and public
keys. Each
member's browser makes an Ed25519 signing key and an X25519 key and announces
both in its join record, signed with that signing key. Every record is
signed and checked against its slot's keys. Invite links also carry the
creator's signing key, a per-invite secret and the invite's place
(`#<room key>.i<invite token>.c<creator key>.s<invite secret>.n<place>`): a
joiner checks the creator's join against the key and that the server gave
it the place the invite was made for, and proves with the secret (a keyed
BLAKE2b hash of the room, place and its keys) that its join came from that
link; the secret never reaches the server. Anyone else becomes a member only
once the creator's app posts a signed `admit` record naming their signing
key; it admits each place once, when it sees joins with a valid proof that
all carry the same keys. (Only the holder of a place's member token can post
as that place, so two different ones mean the server let someone else post
there; it then admits neither.) So the room key alone adds nobody, even with
the server's help. X25519 keys of low order are refused. Each tab remembers the keys
it has seen for each place and the removals, and refuses a later history
that contradicts them. Only slot 0 (the creator) may name the room, label
invites, admit and announce removals. The creator also signs the chat's
settings (whether joins need a password, the member limit, the invite
lifetime) and each invite's expiry. An invite nobody used in time stops
working (the server refuses it, and the creator's tab refuses joins it sees
more than ten minutes late). In a chat with a password, a join's proof is
keyed by the invite secret and an Argon2id key of the password together; a
join whose proof fails closes its place, so each invite allows one guess,
also against a server that posts joins of its own.

**Messages and forward secrecy** ("sender keys", as in Signal and WhatsApp
groups). Each member has a sending chain: a 32-byte chain key `CK`, from which
each message's key is `crypto_kdf(CK, 1, "nbrmmsgk")` and the next chain key is
`crypto_kdf(CK, 1, "nbrmnext")`. Keys are deleted once used, by the sender
and by every reader. A member hands their chain to each other member in a
`keys` record, sealed to that member's X25519 key with `crypto_box_seal`
together with a 16-byte BLAKE2b hash of the room, the sender's slot and the
chain position, so the room key alone reads no message and nobody can hand
on someone else's chain as their own. Each delivery also carries a 16-byte
*commitment* to the chain key at its position (a BLAKE2b hash keyed with it):
every recipient checks theirs, and members who hold that chain check
deliveries to others, so a sender cannot give members different chains for
one place unnoticed. Chains restart from fresh random keys
(a new generation) after a removal and every 50 messages; a removed member
never gets the new ones. A new member receives each chain at its current
position, so they read only what is sent after they join. Readers step a
chain forward only after a message decrypts and its signature checks, at most
1,000 messages ahead, and never move a chain back.

**Receiving keys rotate too.** Each member's X25519 receiving keys are
numbered (0 in their join record, then signed `box` records), and each key
delivery names the number it was sealed to. After a delivery arrives, the
member announces a new key at their next successful check for messages, at
most once every three minutes (each change is a record); the one before is
deleted two minutes later. A
new key is stored in the tab before it is announced, so a lost reply cannot
lose it, and deleted keys are saved as deleted at once. So a delivery
that someone recorded cannot be opened with keys taken from the member's
device afterwards: a later compromise normally exposes the last five
minutes or so. Each tab remembers every member's newest receiving key and refuses
a history that rolls it back or swaps it. A server can still keep a key in
use: by hiding a delivery and that sender's messages from the member (their
app replaces the key whenever it sees new messages it cannot read), or by
showing a member who joined later only an older key of someone's; that
someone is warned when a delivery reaches them sealed to a key they had
replaced more than ten minutes before. A member also checks that the join
record for their own place carries their own signing key, and warns if not.

**Copies of a member's keys.** Each tab saves a hash of every record it
posts before posting it, and keeps it even when posting fails. Every message
also carries an outer Ed25519 signature by its sender over everything
before it, which every reader checks before decrypting, so it cannot be
stripped. A record signed with a member's key that their tab never posted
is a copy's: the tab then ends the room and deletes its keys.

**Forked conversations.** Every message carries *receipts*: for each of the
20 places, the newest record the sender read from it (its place in that
member's chain and a hash of its content), or nothing, so a message's size
does not show what its sender read. A reader who read something else at
that place is told: either that member's receipts are false, or someone,
maybe with the server's help, is showing people different conversations. Every reader also checks each sender's
signed records (key deliveries, and messages by their outer signature,
even ones it cannot read) only move forward in the history: a sender who
splits the room into groups with separate chains has to step back
somewhere, and everyone is told (the server, which can reorder records,
could also cause this). And a reader is told when a sender's keys keep
going to others but not to them, for more than two minutes after they
were let in.

**Chat records** travel as messages, with forward secrecy: a message (maybe
a reply, naming the message's id and sender), a reaction (one of six fixed
emoji, added or taken back, also naming the message's sender), an edit or an
unsend. Ids count per sender. Readers accept an edit or unsend only from the
message's sender, a reaction once per person, and nothing about a message
they do not have. A quote shows what its message said when the reply
arrived, and "Edited since" if it changed. Readers refuse text with control,
format or direction characters (zero-width spaces, soft hyphens, tag
characters and the like), line or paragraph separators, fillers that show
as nothing, variation selectors other than emoji ones, zero-width joiners
and characters Unicode marks as default-ignorable (drawn as nothing, even
unassigned ones), zero-width joiners and non-joiners outside emoji and the
scripts that spell with them (Arabic, Indic and others), stacks of more
than five combining marks on one character, more than two blank or
blank-looking lines in a row, blank lines at the start, spaces at the end,
or nothing visible at all; the app removes them before sending. The flags
of England, Scotland and Wales keep their tag characters; no other tags
are allowed. Names and invite labels may hold at most four digits, none in
brackets, no check marks, not the word "verified", and no more than three
stacked marks, so they cannot pass for the codes and marks the app shows;
the room's name may hold any digits. Names in scripts with
Latin lookalikes (Cyrillic, Greek, Cherokee, Lisu and others) always show
the start of their code, and so do Latin names in a room that has one.

**Formats.** Control: `1 || nonce (24) || ciphertext`. Message:
`2 || generation (4) || index (4) || nonce (24) || ciphertext || outer signature (64)`,
with additional data `nullbin room msg v1 <room> <slot> <generation> <index>`.
The creator's signed `room` record carries the room's name and the time it
ends; the countdown never runs past it, and the app says so when the server
claims an end more than ten minutes later (clocks differ), or when the
record is missing. The plaintext
is `length (4) || JSON || Ed25519 signature (64) || zeros`, padded like
pastes but with a 1 KiB minimum for control records and 2 KiB for messages
(their receipts take about 1.2 KiB), so every message of up to about 600
bytes of UTF-8 text (600 plain letters, fewer with accents or emoji) has
the same size. Signatures cover a context string with the
room, slot (and for messages, generation and index), then the JSON.

**Safety codes** are 30 digits (about 99 bits) from a BLAKE2b hash of a
member's signing key, which signs everything else they announce.

**Endpoints** (all under `/api/v1/rooms`; wrong tokens, unknown and expired
rooms all return `404`, and token checks take the same time whether or not
the room exists; a request that can never work gets `400`, some before any
token check; a valid token can also get `409` for a full room and `410` for
a used or expired invite, which tells whoever holds such an invite whether
the room still exists):

- `POST /api/v1/rooms` with `{"expires_in": 300 | 1800 | 3600 | 10800 | 43200 | 86400 | 259200 | 604800}`,
  and optionally `"max_members"` (2 to 20, default 20) and `"invite_ttl"`
  (300, 900 or 3600 seconds, default 3600: the longest any invite may
  work), returns
  `201` with `id`, `owner_token`, `member_token` and `slot` 0 (the creator);
  `429` when this client network already has 10 live rooms.
- `POST /{id}/invites?ttl=300|900|3600` (with `Nullbin-Owner-Token`;
  `ttl`, how long this invite works, is optional and at most the room's
  `invite_ttl`, which is also its default) returns `201` with a
  single-use `invite_token` and its `slot`; `409` when 20 slots are used, or
  when members and still-usable invites reach `max_members`.
- `POST /{id}/join` (with `Nullbin-Invite-Token`) returns `200` with a pending
  `member_token` and the `slot`; `410` if that invite was used, revoked
  (removed) or older than its `ttl`.
- `POST /{id}/members/{n}/admit` (with `Nullbin-Owner-Token`) grants full
  server permissions after the creator's tab verifies the join proof.
  Requires a pending place with a posted announcement; retries are safe.
- `POST /{id}/records` (with `Nullbin-Member-Token`, `application/octet-stream`,
  41 bytes to 16 KiB) stores one record and stamps it with the sender's slot.
  Before admission, only one immutable announcement is allowed: an exact
  retry returns its existing index, and a different record gets `403`.
  `409` after 1,000 records or 4 MiB, or when the creator's network holds
  4 MiB in its rooms (16 MiB per IPv6 /48).
- `GET /{id}/records?after=n` (with `Nullbin-Member-Token`; `n` up to 1000)
  returns up to 200 records, and 64 KiB, after the first `n`:
  `{"next": m, "expires_in": seconds, "records": [{"from": slot, "data": "<base64>"}]}`,
  streamed under the download bandwidth limits.
- `GET /{id}/members` (owner) returns each used slot's state
  (`invited`, `expired`, `pending`, `joined`, `removed`).
- `POST /{id}/members/{n}/remove` (owner) closes slot `n` (not 0) for good:
  it removes a member, or revokes an invite nobody used yet.
- `DELETE /{id}` (with `Nullbin-Member-Token` of any admitted current member, or the
  owner token) self-destructs the room for everyone.

Invite links look like
`https://host/r/<id>#<room key>.i<invite token>.c<creator key>.s<invite secret>.n<place>`.
Rooms are kept in memory only. The server zeroes a room's stored records
when it ends; copies made while serving them can stay in memory until it is
reused (all of it ciphertext).

</details>

<details>
<summary><strong>Verify a build</strong>: check that a release or a live site matches the source</summary>

Each release is its tagged source plus a `SHA256SUMS` file. The release
workflow builds the tag twice from scratch, checks both builds match, and
records their checksums, so building it yourself gives the same files.

**A release.** In a checkout of the release (replace `v1.2.3`):

```bash
docker build --target artifacts --build-arg VERSION=v1.2.3 --output type=local,dest=out .
sha256sum out/nullbin out/dist/app.js out/dist/app.css out/dist/index.html
```

Compare with the release's `SHA256SUMS`. `nullbin` matches
`nullbin-linux-amd64` or `nullbin-linux-arm64`, depending on your machine.
The three website files are those of the local all-in-one server.

**A website.** Its `/version.json` lists its version, API address, site
address (`site_origin`, used only for the link-preview image), asset paths
and file hashes. Build the same version with the same two addresses, then
compare the downloaded page, script and style with your
build. The page's Subresource Integrity hashes tie the scripts to the page.

A check proves only what was served to you at that moment; a compromised
host could serve different code later or to someone else.

</details>

<details>
<summary><strong>Other ways to deploy</strong>: cloud-init, automatic website builds and custom static hosts</summary>

### New server with cloud-init

[deploy/cloud-init.yaml](deploy/cloud-init.yaml) sets up Option A on a new
Ubuntu 24.04 server. Put your domain in its settings block, point the domain
at the server, and paste the file into your provider's "user data" or
"cloud-init" field when creating the server. It installs Docker, sets up the
firewall and automatic Ubuntu updates, turns off SSH passwords, downloads
the latest release and starts Nullbin. It is installed in `/opt/nullbin`;
manage it with the [usual commands](#run-your-server) from
`/opt/nullbin/deploy`.

The Compose setup is tested in CI; the full cloud-init boot has not been
tested on a real cloud server.

### Automatic website builds

A static host can build the website from Git. Use these settings with a
host that supports `_headers` and `_redirects`:

| Setting | Value |
|---|---|
| Root directory | Repository root |
| Node version | 26 or later |
| Build command | `npm ci --ignore-scripts && npm run build:frontend` |
| Output directory | `web/dist` |
| Environment variables | `NULLBIN_API_ORIGIN=https://api.example.com` and, for link-preview images, `NULLBIN_SITE_ORIGIN=https://paste.example.com` |

Automatic builds follow a branch, so do not point them at `main`. Use a
branch in your own fork that you only move to release tags. Turn off any
feature that injects analytics or rewrites the HTML or JavaScript: it would
break the security policy. Cloudflare's guides:
[Git integration](https://developers.cloudflare.com/pages/get-started/git-integration/),
[Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/),
[custom domains](https://developers.cloudflare.com/pages/configuration/custom-domains/).

### Your own static host

Serve the output folder from the site root, over HTTPS, and:

- serve `index.html` for `/chat`, `/p/<id>`, `/d/<id>` and `/r/<id>`, without
  changing the URL;
- send the headers in `_headers`, including the Content-Security-Policy.
  Without the framing and isolation headers the site refuses to open or
  create anything;
- cache files under `/assets/` (their names contain their hash), but always
  serve a fresh `index.html`;
- add no scripts and change no files.

`web/generated/headers.caddy` has the same headers for Caddy, and
`deploy/Caddyfile` shows the routing.

</details>

<details>
<summary><strong>Development</strong>: build from source and run the tests</summary>

Use Go 1.25 or later and Node.js 26 or later. CI and release tool versions
are pinned in the workflows and the Dockerfile.

**API only** (no Node.js needed):

```bash
go build -tags=api -trimpath -o nullbin ./cmd/nullbin
NULLBIN_API_ONLY=true ./nullbin
```

On Windows PowerShell, build with `-o nullbin.exe`, set
`$env:NULLBIN_API_ONLY = "true"`, and run `./nullbin.exe`.

**All-in-one local server** (website and API in one process, without the
separate website boundary used in production):

```bash
npm ci --ignore-scripts
npm run build
go build -trimpath -o nullbin ./cmd/nullbin
./nullbin
```

Then open `http://127.0.0.1:8080`.

Null Chats live in the server's memory, so outside Docker (whose files
here already turn them off) run it with core dumps off: `ulimit -c 0` first
on Linux and macOS, and on systemd `LimitCORE=0`.

**Website only:** `NULLBIN_API_ORIGIN=https://api.example.com npm run build:frontend`
builds `web/dist`. The API address is fixed at build time; links and API
responses cannot change it.

**Tests:**

```bash
npm run typecheck
npm test
npm run build
go vet ./...
go test -race ./...
go test -tags=api -race ./...
go test -run='^$' -fuzz=FuzzHandler -fuzztime=15s ./internal/server
npm run test:browser
NB_TEST_SPLIT=1 npm run test:browser
```

`npm test` includes a fuzzer for Null Chats: a malicious member who also
runs the server tampers with every room, and each tab must still show only
admitted members, only what people said, keys that only move forward and
every warning it raised. Run it longer with
`NB_ROOM_FUZZ_ROUNDS=2000 node --test web/test/room-fuzz.test.ts`.
The room protocol is specified in [ROOM_PROTOCOL.md](ROOM_PROTOCOL.md),
with a [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of
its core in `proverif/` (section 10 there says how to run it).

Browser tests need Chrome (set `CHROME_PATH` to choose one). They cover
every feature under the real security policy, in both layouts. CI also
tests both Compose deployments over HTTPS. See
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution and release rules.

</details>

## License

Copyright (C) 2026 Jacob Zymet. Nullbin is free software, licensed under the
[GNU Affero General Public License, version 3](LICENSE) only
(AGPL-3.0-only): you may use, change and share it under its terms.

If you run a **modified** version for others to use, the AGPL requires you
to offer them its source code, for example with a link to your fork.
Running an unmodified release needs nothing extra: its source is public
here.

Bundled third-party components keep [their own licenses](THIRD_PARTY_NOTICES).
