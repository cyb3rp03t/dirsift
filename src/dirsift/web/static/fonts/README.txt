Fonts vendored into the package so the console works with no network at all.

ibm-plex-sans-latin.woff2       IBM Plex Sans, latin subset, weight axis 100-700
ibm-plex-sans-latin-ext.woff2   IBM Plex Sans, latin-ext subset (covers the
                                Turkish and East European letters), weight axis
                                100-700
                                SIL Open Font License 1.1, see IBM-PLEX-SANS-OFL.txt
jetbrains-mono-latin.woff2      JetBrains Mono, latin subset, weight axis 400-700
jetbrains-mono-latin-ext.woff2  JetBrains Mono, latin-ext subset, weight axis 400-700
                                SIL Open Font License 1.1, see JETBRAINS-MONO-OFL.txt

All four were taken from the Google Fonts distribution, which serves each face as
a single variable woff2 per subset. The stylesheet pins the weights it uses (400
for text, 600 for the wordmark and headings) with font-weight ranges on the
@font-face rules; the browser draws those instances from the one file. Only the
latin and latin-ext subsets ship. Anything outside them falls back to the system
stack named in dirsift.css.

Sources (recorded for a future refresh, not fetched at run time):
  IBM Plex Sans   https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600
                  files under https://fonts.gstatic.com/s/ibmplexsans/v23/
  JetBrains Mono  https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400..700
                  files under https://fonts.gstatic.com/s/jetbrainsmono/v24/
  IBM Plex Sans licence  https://github.com/IBM/plex  (LICENSE.txt, SIL OFL 1.1)
