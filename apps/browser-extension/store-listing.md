# Store listing

What the extension's pages on addons.mozilla.org (AMO) and the Chrome Web
Store say, kept here to be pasted into each store's form. The packages come
from `scripts/package-extension.sh`.

## Common

- **Name:** Open Secret Manager
- **Summary** (the manifest's description, 128 characters): Fills a login,
  card, or passkey you choose in the Open Secret Manager app into the page
  you are on. Nothing leaves your devices.
- **Category:** AMO: Privacy & Security. Chrome Web Store: Privacy &
  Security (or Tools, where that category is not offered).
- **Homepage:** https://github.com/tksuns12/open-secret-manager
- **Support:** https://github.com/tksuns12/open-secret-manager/issues
- **Privacy policy:** https://github.com/tksuns12/open-secret-manager/blob/main/PRIVACY.md
- **License:** GPL-3.0-only
- **Screenshots** (1280×800 JPEG, a caption over the desktop window's
  preview on sample data), in this order: `store/screenshot-1-login.jpg`,
  `store/screenshot-2-passkey.jpg`, `store/screenshot-3-card.jpg`,
  `store/screenshot-4-vault.jpg`, `store/screenshot-5-devices.jpg`.
- **Store icon:** `store/icon-store-128.png` (96 px in 128). **Small promo
  tile:** `store/promo-tile-440x280.jpg`. All drawn by
  `node scripts/icons.mjs`, except the screenshots.

## Description (English)

Open Secret Manager is a password manager in which each of your devices
keeps its own encrypted vault and the devices sync with each other
directly: no account, no server, no telemetry.

This extension connects your browser to the Open Secret Manager desktop app
on the same computer (macOS; a Linux package is also built). It needs the
app, from https://github.com/tksuns12/open-secret-manager/releases.

- Press the extension's button on a page, and the app shows the logins
  saved for that page's exact address (HTTPS, the same host and port). The
  one you choose is filled; nothing is filled until you choose.
- Cards: the app fills the card you choose, and says which parts go to the
  page and which to a payment provider's frame.
- Passkeys: with the option turned on, a site's request for a passkey goes
  to the app, which asks you before anything is signed.
- The extension never receives a list of what your vault holds, makes no
  network requests, and stores nothing.

The project is young and nobody outside it has reviewed its security yet;
keep a copy of your passwords elsewhere too.

## Description (Korean)

Open Secret Manager는 기기마다 암호화된 vault를 따로 갖고 기기끼리 직접
동기화하는 비밀번호 관리자입니다. 계정도, 서버도, 원격 수집도 없습니다.

이 확장은 같은 컴퓨터의 Open Secret Manager 데스크톱 앱(macOS, Linux
패키지도 있음)과 브라우저를 잇습니다. 앱이 필요합니다:
https://github.com/tksuns12/open-secret-manager/releases

- 페이지에서 확장 버튼을 누르면, 앱이 그 페이지 주소(HTTPS, 같은 호스트와
  포트)로 저장된 로그인을 보여 줍니다. 고른 것만 채우며, 고르기 전에는
  아무것도 채우지 않습니다.
- 카드: 고른 카드를 채우고, 어느 칸이 페이지로, 어느 칸이 결제 대행사의
  프레임으로 가는지 알려 줍니다.
- 패스키: 옵션을 켜면 사이트의 패스키 요청이 앱으로 가고, 서명 전에 앱이
  묻습니다.
- 확장은 vault에 무엇이 있는지 목록을 받지 않고, 네트워크 요청을 하지
  않으며, 아무것도 저장하지 않습니다.

아직 초기 프로젝트이고 외부 보안 검토를 받지 않았습니다. 비밀번호는 다른
곳에도 사본을 두세요.

## Chrome Web Store: privacy practices

- **Single purpose:** fill a login, a card, or a passkey that the owner
  chooses in the Open Secret Manager desktop app into the current page.
- **activeTab:** to read the address and the login or card fields of the
  tab the owner pressed the button on, and fill what they chose there.
- **scripting:** to put the script that finds the fields and fills them
  into that tab, and, with the option on, the script that passes a page's
  passkey request to the app.
- **nativeMessaging:** the only way the extension talks to the desktop app,
  through the native messaging host the app installs.
- **Optional host permission (https://\*/\*):** asked for only when the
  owner turns on passkeys and payment frames in the options; passkey
  requests and a payment provider's frame can come from any site.
- **Remote code:** none; everything runs from the package.
- **Data usage:** the extension handles authentication information (the
  login or passkey the owner chose) only to fill it into the page they are
  on. It does not collect it, store it, or send it anywhere but that page;
  nothing goes to the developer or anyone else. The certifications (not sold
  to third parties, not used for unrelated purposes, not used for credit)
  all hold.

## AMO

- **Data collection** (in the manifest): none.
- **Source code:** required, as the scripts are bundled from TypeScript.
  Upload `open-secret-manager-extension-<version>-source.zip`; the notes
  for reviewers: "Node 24 and npm: in `apps/browser-extension`, run
  `npm ci && npm run build`; `dist/firefox` is the add-on. See README.md
  there."
