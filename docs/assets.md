# Visual assets and their licenses

PLANNING.md §7.6: every icon, font, and illustration the app ships is listed here with its source and license.

| Asset | Where | Source | License |
|---|---|---|---|
| App icon (sparkles on a teal tile) | `src-tauri/icons/icon.svg`, PNG and ICO files generated from it with `npm run tauri icon`, a copy in `ui/public/favicon.svg`, and the `Logo` component in `ui/src/components/logo.tsx` | Drawn for OpenJanitor | GPL-3.0-or-later, like the rest of the project |
| Geist font | `@fontsource-variable/geist` (npm), bundled with the UI | Vercel, packaged by Fontsource | SIL Open Font License 1.1 |
| Interface icons | `lucide-react` (npm) | Lucide | ISC |

To regenerate the app icons after changing `icon.svg`:

```powershell
npm run tauri icon src-tauri/icons/icon.svg -- --output src-tauri/icons
```

Then delete the files a Windows-only app doesn't need: the `android/` and `ios/` folders, `icon.icns`, `64x64.png`, `StoreLogo.png`, and the `Square*Logo.png` files.
