# Stepwise website

The marketing site for Stepwise, a private, on-device Mac app that turns the clicks you make into a
step-by-step guide. This repository holds only the static site and its deployment config; the app
itself is not in here.

- `website/` is the site: plain HTML and CSS, no JavaScript, no third-party requests.
- `render.yaml` is the Render Blueprint. All response headers (a strict Content-Security-Policy and
  friends) are defined there.
- `scripts/check_site.py` enforces the security, link, accessibility and contrast rules. The
  "Site checks" workflow runs it on every push.
- `website/downloads/` holds the notarized installer and `website/appcast.xml` is the signed update
  feed the app reads.
