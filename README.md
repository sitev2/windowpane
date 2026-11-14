# Windowpane

A browser inside a browser. Open your deployed address in Safari (or any browser) and use the tabs, address bar and bookmarks inside it.

## Deploy on Render
1. Create a new GitHub repository and upload everything in this folder (server.js, package.json, render.yaml, public/).
2. On render.com: New > Blueprint (or New > Web Service), pick that repository.
3. When asked for the PASSWORD variable, enter a long password you will remember. The server will not start without it.
4. Wait for the deploy, then open the https://...onrender.com address. Sign in, then add it to your iPad Home Screen (Share > Add to Home Screen).

The free plan sleeps after about 15 minutes of no use, so the first load after a break takes up to a minute.

## Also host the interface on GitHub Pages
In the repo: Settings > Pages > deploy from branch main, folder /docs. The page at https://<user>.github.io/windowpane/ signs in to your Render server (ALLOW_ORIGIN in render.yaml must match your github.io origin).

## Run locally
    node server.js
    open http://127.0.0.1:8080
