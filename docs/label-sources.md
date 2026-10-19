# Sources of the credential label words

Each word in `maisecrets/detection/rules/labels/<language>.txt` (except `en.txt` and `de.txt`) comes from a
reviewed translation in a large open-source project. The table names the file and the string
(msgid, key or English source string) that the word translates. A word with no source row is not
in a file. The label files add the spellings people type for the same word: without diacritics
(`cle secrete`), with `_` or `-` between the words, and with a prefix such as `db_`.

The files were read on 2026-09-28 from the default branch of each project.

| Language | Word | Project | File | Translates |
|---|---|---|---|---|
| es | clave de acceso | Nextcloud | [apps/files_external/l10n/es.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/es.json) | `Access key` |
| es | clave secreta | Nextcloud | [apps/files_external/l10n/es.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/es.json) | `Secret key` |
| es | clave de la API | Nextcloud | [apps/files_external/l10n/es.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/es.json) | `API key` |
| es | credenciales | Nextcloud | [apps/settings/l10n/es.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/es.json) | `Credentials` |
| it | chiave di accesso | Nextcloud | [apps/files_external/l10n/it.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/it.json) | `Access key` |
| it | chiave segreta | Nextcloud | [apps/files_external/l10n/it.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/it.json) | `Secret key` |
| it | chiave API | Nextcloud | [apps/files_external/l10n/it.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/it.json) | `API key` |
| it | segreto del client | Nextcloud | [apps/files_external/l10n/it.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/it.json) | `Client secret` |
| it | credenziali | Nextcloud | [apps/settings/l10n/it.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/it.json) | `Credentials` |
| fi | salasana | Django | [django/contrib/auth/locale/fi/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/fi/LC_MESSAGES/django.po) | `Password` |
| fi | salasana | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_fi.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_fi.properties) | `password` |
| fi | salainen avain | Nextcloud | [apps/files_external/l10n/fi.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fi.json) | `Secret key` |
| fi | pääsyavain | Nextcloud | [apps/files_external/l10n/fi.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fi.json) | `Access key` |
| fi | API-avain | Nextcloud | [apps/files_external/l10n/fi.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fi.json) | `API key` |
| fi | asiakassalaisuus | Nextcloud | [apps/files_external/l10n/fi.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fi.json) | `Client secret` |
| fi | tunnistetiedot | Nextcloud | [apps/files_external/l10n/fi.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fi.json) | `Global credentials` |
| sv | lösenord | Django | [django/contrib/auth/locale/sv/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/sv/LC_MESSAGES/django.po) | `Password` |
| sv | lösenord | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_sv.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_sv.properties) | `password` |
| sv | hemlig nyckel | Nextcloud | [apps/files_external/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/sv.json) | `Secret key` |
| sv | hemlig åtkomstnyckel | Nextcloud | [apps/files_external/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/sv.json) | `Secret access key` |
| sv | åtkomstnyckel | Nextcloud | [apps/files_external/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/sv.json) | `Access key` |
| sv | API-nyckel | Nextcloud | [apps/files_external/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/sv.json) | `API key` |
| sv | klienthemlighet | Nextcloud | [apps/files_external/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/sv.json) | `Client secret` |
| sv | inloggningsuppgifter | Nextcloud | [apps/settings/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/sv.json) | `Credentials` |
| sv | autentiseringsuppgifter | Nextcloud | [apps/files_external/l10n/sv.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/sv.json) | `Storage credentials` |
| pl | hasło | Django | [django/contrib/auth/locale/pl/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/pl/LC_MESSAGES/django.po) | `Password` |
| pl | hasło | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_pl.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_pl.properties) | `password` |
| pl | klucz dostępu | Nextcloud | [apps/files_external/l10n/pl.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pl.json) | `Access key` |
| pl | tajny klucz | Nextcloud | [apps/files_external/l10n/pl.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pl.json) | `Secret key` |
| pl | klucz API | Nextcloud | [apps/files_external/l10n/pl.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pl.json) | `API key` |
| pl | poświadczenia | Nextcloud | [apps/settings/l10n/pl.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/pl.json) | `Credentials` |
| tr | parola | Django | [django/contrib/auth/locale/tr/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/tr/LC_MESSAGES/django.po) | `Password` |
| tr | şifre | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_tr.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_tr.properties) | `password` |
| tr | gizli anahtar | Nextcloud | [apps/files_external/l10n/tr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/tr.json) | `Secret key` |
| tr | gizli erişim anahtarı | Nextcloud | [apps/files_external/l10n/tr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/tr.json) | `Secret access key` |
| tr | erişim anahtarı | Nextcloud | [apps/files_external/l10n/tr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/tr.json) | `Access key` |
| tr | API anahtarı | Nextcloud | [apps/files_external/l10n/tr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/tr.json) | `API key` |
| tr | kimlik doğrulama bilgileri | Nextcloud | [apps/settings/l10n/tr.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/tr.json) | `Credentials` |
| ko | 비밀번호 | Django | [django/contrib/auth/locale/ko/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/ko/LC_MESSAGES/django.po) | `Password` |
| ko | 비밀번호 | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_ko.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_ko.properties) | `password` |
| ko | 패스워드 | Nextcloud | [apps/settings/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/ko.json) | `You deleted app password "{token}"` |
| ko | 암호 | Nextcloud | [apps/files_external/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/ko.json) | `Password` |
| ko | 토큰 | Nextcloud | [apps/settings/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/ko.json) | `Could not delete the app token` |
| ko | API 키 | Nextcloud | [apps/files_external/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/ko.json) | `API key` |
| ko | 비밀 키 | Nextcloud | [apps/files_external/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/ko.json) | `Secret key` |
| ko | 접근 키 | Nextcloud | [apps/files_external/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/ko.json) | `Access key` |
| ko | 인증 정보 | Nextcloud | [apps/settings/l10n/ko.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/ko.json) | `Credentials` |
| th | รหัสผ่าน | Django | [django/contrib/auth/locale/th/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/th/LC_MESSAGES/django.po) | `Password` |
| th | รหัสผ่าน | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_th.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_th.properties) | `password` |
| th | รหัสผ่านใหม่ | Django | [django/contrib/auth/locale/th/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/th/LC_MESSAGES/django.po) | `New password` |
| th | รหัสผ่านเก่า | Django | [django/contrib/auth/locale/th/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/th/LC_MESSAGES/django.po) | `Old password` |
| th | โทเค็น | Nextcloud | [core/l10n/th.json](https://github.com/nextcloud/server/blob/master/core/l10n/th.json) | `State token missing` |
| fr | mot de passe | Django | [django/contrib/auth/locale/fr/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/fr/LC_MESSAGES/django.po) | `Password` |
| fr | mot de passe | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_fr.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_fr.properties) | `password` |
| fr | clé d'accès | Nextcloud | [apps/files_external/l10n/fr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fr.json) | `Access key` |
| fr | clé d’accès secrète | Nextcloud | [apps/files_external/l10n/fr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fr.json) | `Secret access key` |
| fr | clé secrète | Nextcloud | [apps/files_external/l10n/fr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fr.json) | `Secret key` |
| fr | clé API | Nextcloud | [apps/files_external/l10n/fr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fr.json) | `API key` |
| fr | secret client | Nextcloud | [apps/files_external/l10n/fr.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/fr.json) | `Client secret` |
| fr | identifiants | Nextcloud | [apps/settings/l10n/fr.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/fr.json) | `Credentials` |
| nl | wachtwoord | Django | [django/contrib/auth/locale/nl/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/nl/LC_MESSAGES/django.po) | `Password` |
| nl | wachtwoord | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_nl.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_nl.properties) | `password` |
| nl | geheime sleutel | Nextcloud | [apps/files_external/l10n/nl.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/nl.json) | `Secret key` |
| nl | API-sleutel | Nextcloud | [apps/files_external/l10n/nl.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/nl.json) | `API key` |
| nl | inloggegevens | Nextcloud | [apps/settings/l10n/nl.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/nl.json) | `Credentials` |
| pt | senha | Django | [django/contrib/auth/locale/pt_BR/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/pt_BR/LC_MESSAGES/django.po) | `Password` |
| pt | senha | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_pt_BR.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_pt_BR.properties) | `password` |
| pt | palavra-passe | Django | [django/contrib/auth/locale/pt/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/pt/LC_MESSAGES/django.po) | `Password` |
| pt | palavra-passe | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_pt.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_pt.properties) | `password` |
| pt | chave de acesso | Nextcloud | [apps/files_external/l10n/pt_PT.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pt_PT.json) | `Access key` |
| pt | chave da acesso | Nextcloud | [apps/files_external/l10n/pt_BR.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pt_BR.json) | `Access key` |
| pt | chave secreta | Nextcloud | [apps/files_external/l10n/pt_BR.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pt_BR.json) | `Secret key` |
| pt | chave API | Nextcloud | [apps/files_external/l10n/pt_BR.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pt_BR.json) | `API key` |
| pt | segredo de cliente | Nextcloud | [apps/files_external/l10n/pt_PT.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pt_PT.json) | `Client secret` |
| pt | segredo do cliente | Nextcloud | [apps/files_external/l10n/pt_BR.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/pt_BR.json) | `Client secret` |
| pt | credenciais | Nextcloud | [apps/settings/l10n/pt_BR.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/pt_BR.json) | `Credentials` |
| da | adgangskode | Django | [django/contrib/auth/locale/da/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/da/LC_MESSAGES/django.po) | `Password` |
| da | adgangskode | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_da.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_da.properties) | `password` |
| da | kodeord | Nextcloud | [apps/files_external/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/da.json) | `Password` |
| da | adgangsnøgle | Nextcloud | [apps/files_external/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/da.json) | `Access key` |
| da | hemmelig nøgle | Nextcloud | [apps/files_external/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/da.json) | `Secret key` |
| da | hemmelig adgangsnøgle | Nextcloud | [apps/files_external/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/da.json) | `Secret access key` |
| da | API nøgle | Nextcloud | [apps/files_external/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/da.json) | `API key` |
| da | klient hemmelighed | Nextcloud | [apps/files_external/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/da.json) | `Client secret` |
| da | legitimationsoplysninger | Nextcloud | [apps/settings/l10n/da.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/da.json) | `Credentials` |
| nb | passord | Django | [django/contrib/auth/locale/nb/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/nb/LC_MESSAGES/django.po) | `Password` |
| nb | passord | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_no.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_no.properties) | `password` |
| nb | tilgangsnøkkel | Nextcloud | [apps/files_external/l10n/nb.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/nb.json) | `Access key` |
| nb | hemmelig nøkkel | Nextcloud | [apps/files_external/l10n/nb.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/nb.json) | `Secret key` |
| nb | API-nøkkel | Nextcloud | [apps/files_external/l10n/nb.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/nb.json) | `API key` |
| nb | klient-hemmelighet | Nextcloud | [apps/files_external/l10n/nb.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/nb.json) | `Client secret` |
| nb | påloggingsdetaljer | Nextcloud | [apps/settings/l10n/nb.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/nb.json) | `Credentials` |
| cs | heslo | Django | [django/contrib/auth/locale/cs/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/cs/LC_MESSAGES/django.po) | `Password` |
| cs | heslo | Keycloak | [themes/src/main/resources-community/theme/base/login/messages/messages_cs.properties](https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources-community/theme/base/login/messages/messages_cs.properties) | `password` |
| cs | hesla | Django | [django/contrib/auth/locale/cs/LC_MESSAGES/django.po](https://github.com/django/django/blob/main/django/contrib/auth/locale/cs/LC_MESSAGES/django.po) | `Password confirmation` |
| cs | přístupový klíč | Nextcloud | [apps/files_external/l10n/cs.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/cs.json) | `Access key` |
| cs | tajný klíč | Nextcloud | [apps/files_external/l10n/cs.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/cs.json) | `Secret key` |
| cs | klientské tajemství | Nextcloud | [apps/files_external/l10n/cs.json](https://github.com/nextcloud/server/blob/master/apps/files_external/l10n/cs.json) | `Client secret` |
| cs | přihlašovací údaje | Nextcloud | [apps/settings/l10n/cs.json](https://github.com/nextcloud/server/blob/master/apps/settings/l10n/cs.json) | `Credentials` |

## Words left out

A label word that is also an ordinary word in running text gives false positives: `palabra clave: sostenibilidad` is prose, not a secret. These words stay out of the files, or the regex takes them only in a label position. `tests/test_label_languages.py` checks prose with them.

| Language | Word | Why |
|---|---|---|
| es | clave | An ordinary word: palabra clave (keyword), la clave del éxito. Only clave de acceso, clave secreta and clave de la API are labels. Measured again on 2026-10-16 with a value in the shape of a password after `clave:`: it stays out, because clave is also a code or an id (Mexico: `clave: CURP-ABCD010101`, `clave: LOTE-2024-001`, `clave: B2B-Ventas`), and a false hit blocks a typed prompt. |
| es | secreto, cliente secreto | secreto alone is prose; cliente secreto (Nextcloud, Client secret) reads as a secret customer. |
| it | chiave, segreto | Ordinary words: parola chiave (keyword). Only the labels of two or more words. |
| it | parola d'ordine | No source uses it; Italian interfaces write password. |
| fi | salaisuus, avain | Ordinary words (a secret, a key). Only asiakassalaisuus and the avain compounds. |
| fi | tilitiedot | Nextcloud settings translates Credentials so, but it also means bank account details. |
| sv | nyckel | An ordinary word (key). Only the compounds and hemlig nyckel. |
| pl | klucz | An ordinary word (key). Only the two-word labels. |
| tr | anahtar | An ordinary word: anahtar kelime (keyword). Only the two-word labels. |
| tr | şifreleme, şifreli, deşifre | Encryption, encrypted, decipher: şifre excludes them (`şifreleme: AES-256-GCM` is no secret). |
| ko | 암호화, 암호문 | Encryption and ciphertext: 암호 counts only as a word alone. |
| ko | 키 | Alone it means key and also height (키: 180센티미터). Only API 키, 비밀 키, 접근 키. |
| th | รหัส | Alone it means code or number (รหัสสินค้า, product code). Only รหัสผ่าน. |
| th | ข้อมูลส่วนตัวสำหรับเข้าระบบ | Nextcloud settings translates Credentials so; a sentence, not a label. |
| fr | clé | An ordinary word: mot clé (keyword). Only the labels of two or more words. |
| fr | identifiant | The singular is the user name, not a secret. Only the plural identifiants. |
| fr | phrase de passe | No reviewed source was checked; the English pass takes passe at a word start. |
| pt | chave | An ordinary word: palavra-chave (keyword). Only the labels of two or more words. |
| pt | código secreto, chave de acesso segreda | Nextcloud pt_PT translations of Secret key and Secret access key: código secreto is also a promotion code in prose, and segreda is a misspelling. |
| da | nøgle | An ordinary word (key). Only the compounds and hemmelig nøgle. |
| nb | nøkkel | An ordinary word (key). Only the compounds and hemmelig nøkkel. |
| cs | klíč, tajemství | Ordinary words (a key, a secret). Only the two-word labels. |
| all | passphrase, PIN | No label word of its own was found in the sources. A PIN is short digits, which the value filters refuse (fewer than 8 characters). |
| all | token | The Latin-script languages write token, which en.txt takes. Only Korean 토큰 and Thai โทเค็น are in their files. |

## Words the denylist has already

detect-secrets lists `contraseña` and `contrasena` (Spanish; Django and Keycloak `password`), and
`password` (the Italian translation in Django and Keycloak). `es.txt` and `it.txt` do not repeat them.
