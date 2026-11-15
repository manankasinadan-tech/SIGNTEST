# SignerLAB

Inspecteur et vérificateur cryptographique avancé de signatures APK pour Android, conçu avec Kotlin et Jetpack Compose (Material 3).

## Fonctionnalités

- **Détection cryptographique multi-schémas** : Vérification complète via `com.android.tools.build:apksig` et analyse binaire directe pour :
  - **V1** (JAR / `META-INF/*.MF`, `.SF`, `.RSA`/`.DSA`/`.EC`)
  - **V2** (APK Signature Scheme v2)
  - **V3 & V3.1** (Rotation de clés, plage SDK, `SigningCertificateLineage`)
  - **V4** (Vérification des fichiers compagnons `.idsig`)
  - **SourceStamp** (v1 / v2, certificat et horodatage)
  - **Inspection APK Signing Block** (offset, taille et liste complète des blocs ID)
- **Rapport cryptographique complet** :
  - Identité APK (`label`, `versionName`, `versionCode`, `packageName`, `minSdk`/`targetSdk`) et empreintes du fichier (`SHA-256`, `MD5`, `CRC32`)
  - Certificats détaillés (`X.509`, version, numéro de série décimal/hex, propriétaire, émetteur / auto-signé, validité, algorithme, `Code de hachage`, `CRC32`, `MD5`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `Base64 du certificat`, `Bits de signature`, `Clé publique`, `Base64 de signature`, extensions X.509)
- **Gestionnaire de fichiers intégré en popup** :
  - Sélection simple ou multiple d'APK
  - Navigation locale (`/storage/emulated/0`, `Download`) et dossiers système protégés via Root (`/system`, `/data/app`)
  - Repli vers le sélecteur système Android (SAF)
- **Activation rapide des autorisations** :
  - Boutons directs dans l'interface pour activer l'accès au stockage (`MANAGE_EXTERNAL_STORAGE` / `READ_EXTERNAL_STORAGE`) et l'élévation Root (`su`)
- **Interface bilingue & adaptative** :
  - Français par défaut avec bascule instantanée Français / Anglais
  - Suivi automatique du thème système Clair / Sombre
  - Exportation du rapport (**Copier**, **`.txt`**, **`.json`**)

## Compilation locale & GitHub Actions

Le dépôt inclut le workflow `.github/workflows/android-ci.yml` qui exécute automatiquement `:app:testDebugUnitTest` et `:app:assembleDebug` sur chaque push ou pull request.

En local (avec Gradle 9.3.1 installé) :

```bash
gradle :app:testDebugUnitTest :app:assembleDebug
```
