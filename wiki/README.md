# Publishing this wiki

GitHub wikis live in a **separate git repository** (`<repo>.wiki.git`), so this folder
is the source of truth and the wiki is published from it.

## One-time setup

```powershell
# create the first page in the browser once (any content), then:
git clone https://github.com/xhimnijx/Radix.wiki.git radix-wiki
```

## Publish (repeat whenever these pages change)

```powershell
Copy-Item wiki\*.md radix-wiki\ -Force
cd radix-wiki
git add -A
git commit -m "docs(wiki): sync from main repository"
git push
```

The wiki then appears at <https://github.com/xhimnijx/Radix/wiki>.

## Why not edit the wiki directly?

Because the canonical documentation is the `vault/` folder in the main repository, and a
wiki edited only in the browser drifts. These pages are deliberately short and point at
the vault for depth.
