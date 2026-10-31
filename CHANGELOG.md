# Changelog

## Unreleased

## [0.8.6] - 2026-10-31

### Features

- when the name service does not answer, the AI tells you once per session (d77c85f)
- a remote detector asks the service for organisations and places when classes names them (7a66d21)
- /maisecrets:ner local, url or off switches names from a NER service on with one prompt (03f3c5b)
- the reference NER service returns organisations, places and dates on request (cbe5f07)
- examples/ner_service.py takes --host (44563e8)
- the ssh question names what keeps a command off the read list (cc4338e)

### Fixes

- a service whose person class is PERSON keeps it when more classes are asked for (f5197d4)
- review findings on /maisecrets:ner and the probe (cf5ad7c)
- the spaCy NER backend keeps the German PER label (4ec6f0c)
- ner_service.py imports on Windows (87e489f)
- access, pass and cookie words keep a revision label a credential (8abadf1)
- a credential word glued into a revision label keeps the hit (e2ff587)
- a revision label with a credential word stays a credential label (70450a5)
- a commit after its label is no secret (eb73af5)

### Dependencies

- update dependency presidio-analyzer to v2.2.366 (9ab8ffe)

## [0.8.5] - 2026-10-30

### Features

- a message to another Claude session goes out with placeholders instead of being dropped by the receiver (79b3bee)
- finds a BitLocker recovery key by its check digits, bare and after any label (28f61cc)
- detects Composio org and user API keys (oak_, uak_) (db767dc)

### Fixes

- an update word before an IP address no longer makes it a version (58a9ff5)
- numbers after the word claim or prior authorization are no US insurance id (e4ab11e)
- a paging cursor, a file key, the time of a secret or a version number in an API answer is no secret (ae23262)

### Dependencies

- the new Presidio labels match in any case; five code shapes and two context words that fired on developer text stay out (a9af4ad)
- keep the skip list's line, a belief anchors on it (35152f2)
- Presidio 2.2.365 with 13 new recognizers for South Africa, Canada, the Philippines and US health records (6e35408)
- update dependency presidio-analyzer to v2.2.365 (b7c8dc9)

## [0.8.4] - 2026-10-30

### API

- new and provisional: remote.RemoteDetector, RemoteStatus, Result, Detector.findings_with, (b909b1d)

### Features

- an optional name service adds names in tool results, and the library can ask it too (b909b1d)

## [0.8.3] - 2026-10-29

### Features

- ask before a stored secret goes to a host it never went to (secret_destinations protect) (0d40b63)
- the settings show how often asking before a new host would have asked in your last 30 days (594c9e8)
- detects Labelbox API keys and the Tailscale key form tskey-k…CNTRL- (bff9b2b)

### Fixes

- test results after PASS:, a heading after Basic, and calendar or message ids are no longer masked (3e781e6)
- SSH algorithm names such as curve25519-sha256@libssh.org are no e-mail addresses (5b9b4f2)
- a report or notice matches the model's text only as written or escaped (84d0c08)
- a background command's notice no longer blocks the session (f5849d0)
- hides a database URL password that holds a raw # or ? (afaa446)
- keeps masking a person's long user name that ends in -bot (fea968b)
- keeps masking a person's long user name that ends in -svc (5a113c8)
- keeps masking a person's user name that starts with a service word or ends in one after a long name (aec3aa8)
- leaves the user names of bots and service accounts as text (b0141aa)

## [0.8.2] - 2026-10-26

### Features

- password labels in all 19 supported languages are read by default, whatever the system language (bff0988)

### Fixes

- a phone number after a phone word and a passport number after an EDIFACT + are masked whole again (9c4c9b0)
- a long tool result is scanned about a tenth faster with all label languages on (cea661b)
- a full name after a self-introduction in French, Spanish, Italian, Dutch, Swedish, Danish, Norwegian, Polish, Portuguese, Czech, Finnish, Romanian or German is masked (ec1241e)
- a date of birth after its label in Dutch, Swedish, Danish, Norwegian, Finnish, Polish, Czech, Turkish, Russian, Ukrainian, Romanian, Greek, Arabic, Japanese, Chinese or Korean is masked (b9c7d84)
- personal data in JSON inside a JSON string or in a Python dict print is masked by its field names (94c3105)
- personal data in YAML, .env, INI, log key=value lines, SQL UPDATE and WHERE, and PHP print_r is masked by its field names (9b53c7d)
- a password under a password column of a table or a SQL INSERT is masked, in every label language (1cf90f0)
- a person's field name in Polish, Dutch, Swedish, Spanish, Italian, French or Portuguese, or as a short form, names its column (f49c8a1)
- a Chinese or Japanese sentence after a password label, such as the hint of a sign-up form, is no password (c404a94)
- the password labels of all languages cost no time on text without them (89d7f5e)
- an ordinary word after a label in a tool result is no longer masked in every later tool result (c39a27a)
- a medical record number that starts with its own label, such as MRN and digits in one token, is masked whole (52f255f)
- two words after a bare Student: label that a sentence goes on from stay text (167360c)
- a table or record with a first-name and a last-name column masks both names (d4a20c6)
- the values of a SQL dump's INSERT without a column list are named by the CREATE TABLE above it (b1ec7ae)
- an HTML table of fields and values, one <th> and one <td> per row, is read as one record (338ac17)
- a name inside an XML element named by a person label, such as <card_holder> or <customerName>, is masked (f1adb45)
- a name after a key that joins a role and name, such as account_holder_name or investorName, is masked (f988689)
- a name after a key that names a person's role, such as payer, policyholder or recipient, is masked (c396c18)
- a first or last name that is also a word is masked next to another name part of the record (ec4945d)
- a driving licence or passport number after driverLicense, passportNumber, Führerschein or Pasaporte is masked (a561945)
- a Dutch, Swedish, French, Spanish or Italian street after an address label is masked (59bf002)
- a US address right after a "home address" or "residential address" label is masked, also next to a company name (7a9fee9)
- a street line after "located at", "situated at" or "property at" is masked (f5a434b)
- a user name in an apposition is masked (the user name, value, or the user name (value)) (742a2b3)
- a US phone number in the (ddd) ddd-dddd form after "reached at" or "me at" is masked (c6b6cc6)
- an account name after a user id label is masked, and a number, UUID or code stays text (443f529)
- a birth date after "Date of birth," or a bold "**DOB:**" label is masked (fbcb91f)
- a birth date, phone number or ID in a two-column Markdown table without a header row is masked (96b3104)

## [0.8.1] - 2026-10-25

### Features

- the client shows what maisecrets does while a hook runs (8d7a29e)
- ms:( says what a value is masked as and whether it is found alone (9d8295c)

### Fixes

- the cap of stored values in a session names placeholders and uses, not keys and resolves (410048e)
- when maisecrets cannot run or cannot finish, the message says what to do next (60f9581)
- a refusal or a permission prompt for a tool call says what to check, without codes (503c23b)
- the notices, tips and command outputs say what happens in words you know (e93783e)
- every text names a command that works for the person who reads it (8990742)
- a name or phone number found by the words around it is no longer listed as a format found alone (20450b3)

## [0.8.0] - 2026-10-24

### Breaking

- a library caller gets a TypeError for a text that is not a str, and LazyRegex is gone (bb0edb8)

### API

- the JSON entry point accepts the optional request key context.fields (additive) (25609f3)
- scan and findings take an optional keyword argument fields, the field names of values (additive) (e82049b)
- the offsets of a Match are defined as Unicode code points of the scanned str (text[start:end] == value) (016583d)
- Detector.scan and Detector.findings raise TypeError for a text that is not a str (None and bytes included); a str subclass is accepted (bb0edb8)
- LazyRegex is removed from maisecrets.detection (deprecated in 0.7.0); give user_rule the pattern as a string (bb0edb8)
- new stable name maisecrets.detection.TYPES and the data file maisecrets/detection/types.json (85b6cc3)

### Features

- the JSON entry point takes context.fields, the field names of values (25609f3)
- a library caller can give the field name of a value, and the name counts as a label (e82049b)
- a caller in any language scans text with python3 -m maisecrets.detection (contract maisecrets.detect/1) (1ef231b)
- the library publishes its type vocabulary, each type with its family and class (85b6cc3)

### Fixes

- the release gate names the baseline of an approved minor or major version (b9a56dc)

## [0.7.20] - 2026-10-24

### Features

- finds a Fireworks AI API key and an Infisical service token without a label (ff957f7)

### Fixes

- the directory can read the hook code, as no file is over its size limit any more (9748721)

## [0.7.19] - 2026-10-23

### Fixes

- the directory can read the betterleaks rules, in parts and without a literal key (87289cd)

## [0.7.18] - 2026-10-23

### Fixes

- the directory version ships no design documents and no rule source it never reads (dbab8e6)
- no rule comment carries an example in the shape of a real token (bdb18c6)

## [0.7.17] - 2026-10-23

### Fixes

- the directory can read each detection file, as none is over its size limit any more (b4dd82f)

## [0.7.16] - 2026-10-23

### Fixes

- the format report link comes only for a value with a fixed start, and fits one line (6d2fca7)
- the directory version names the mod in its own hooks file again (e83527e)
- a Cloudflare Access service token secret is found with any checksum letters, as Cloudflare documents it (c3ca1be)

## [0.7.15] - 2026-10-23

### Fixes

- the directory version declares the mod as a module of hooks/hooks.json (320cc76)

## [0.7.14] - 2026-10-23

### Security

- a long run of spaces or "!" after a password word no longer stalls the scan (5e107b0)

## [0.7.13] - 2026-10-23

### Fixes

- an Azure client secret at the end of a sentence is found (62ebee1)

## [0.7.12] - 2026-10-23

### Fixes

- a link into a hexpm repository no longer gives a Hex key (044d84e)

## [0.7.11] - 2026-10-23

### Features

- finds passwords and keys after Russian, Chinese and Japanese labels (3abff8d)

### Fixes

- a private key after a label is masked as one whole block (d6629a1)

## [0.7.10] - 2026-10-23

### Features

- detects 47 more token formats from the providers' own code and documentation (99f8f6f)
- finds the value of a Kubernetes env entry whose name is a password or a key (955142c)
- finds keys and passwords in more typed sentences, such as "my stripe key is <value>" (0baf629)
- finds a password in a note line such as "host (pw:<value>)", "(ID/PW:<value>)" or "-pwd:<value>" (669a13f)
- finds Laravel's APP_KEY and each key of Strapi's APP_KEYS in an .env file (ba5a771)
- finds the password of a database URL that holds an unescaped sign such as ! $ & or + (9d752f1)
- finds the default of a Terraform variable whose name is a key or a password (1e12204)
- finds the keys and salts that PHP's define() sets, such as the WordPress salts in wp-config.php (f5bfdc2)
- detects 72 more token formats that providers define in their own code (35b1a01)
- ms:(…) offers to report the format of a value maisecrets did not catch, with its shape only (8ad067d)
- masks eight more token formats that Trivy, Veles, nuclei and titus know (6251547)
- masks 16 more provider keys after the provider's word and a key label (32e21e4)

### Fixes

- a Zapier catch hook URL is found whole with its https:// scheme (8f60527)
- a Fly.io token of several macaroons is found whole again (23df0ec)
- a key at the end of a sentence is found again: "the key is <token>." or "(<token>)" (0ba8945)
- a hex digest after nfp_ is no Netlify token, and the C29 belief anchors the new answer line (2fac9ae)
- an Akamai host name is no longer taken for an EdgeGrid client token (2c43deb)
- a token at the end of a sentence no longer takes the full stop or colon into the value (845c20c)

## [0.7.9] - 2026-10-22

### Features

- masks 109 more token formats researched from the providers' own documentation (72e05cd)
- masks 97 more token formats with a fixed prefix without a label (9833546)
- masks a Storyblok personal access token without a label (71d376d)

### Fixes

- the release tree builder reads git output as UTF-8 on every platform (4e41130)
- the directory version ships a short README and the prefix rules as JSON (d2621b2)

## [0.7.8] - 2026-10-22

### Fixes

- the plugin ships no text that the Anthropic directory reads as a credential (008abf2)

## [0.7.7] - 2026-10-22

### Features

- masks a US home address written on one line (eabce9d)
- masks a password in three more sentence forms (8727587)
- masks an API key or token named in a sentence (b1e277b)

### Fixes

- the release gate replaces a local path also where JSON escapes it (7bf9127)
- an encoded token after a key word stays to the tool channel's decoder (c896d38)
- a one-line US address after a named place stays text (57186af)
- the software table rule holds back only the new anchors, so a birth date in a CSV row with a sku still names its person (4eea0b3)
- the software table rule applies only with one personal column, so an order record with a customer stays a person's (41a1e65)
- a phone number named in a sentence after a contact label is masked again (Escalation contact: Contact the coordinator at …) (237020b)
- a table of software and a test account are no person's record (500ef2e)
- a date of birth makes a row a person's only when it lies 12 years back, so a release table's date stays text (d5866f2)
- a row with a date of birth under its own name counts as a person's record, so its user name and address are masked (4c3b4a3)
- a person's address and ids in a record under more field names (Property Address, Health Plan Beneficiary Number, MedicalRecordNumber, User ID) (f377ca3)

## [0.7.6] - 2026-10-22

### Fixes

- a company's "we can help you at" and an id after "Contact:" stay text (aee4e79)
- masks a person's own number in a sentence (reach out to me at, my number is), while a company's line stays text (a77baf1)
- masks a phone number after a contact label, after "Fax number for notice:" and with four counting digits at its end (5eabe63)

## [0.7.5] - 2026-10-22

### Fixes

- a blocked message from another session is recognised as one, so its text never goes into your clipboard (461c44c)
- a role name or a given and family name written in camel case (candidateName, givenName) counts as its column (b33eb46)
- fixture names such as Foo Bar or Jane Doe in a first and last name field stay text (c0a0e49)
- masks the name column of a candidate, client, player or recipient in a table of personal records (271ec63)
- masks a first or last name in a record field when the record also holds a person's data (0727d95)

### Security

- a placeholder in a message from another session no longer lets this session use its value (024af1c)
- a message from another Claude session with a secret is blocked again instead of reaching the model (9bc4b68)

## [0.7.4] - 2026-10-21

### Fixes

- a message from another Claude session is rewritten with placeholders instead of being lost in a block (3cc6b07)
- a phone number written as one run of digits is masked after a phone word (Telefon: 0999…, +49…) (4350e18)

## [0.7.3] - 2026-10-21

### Fixes

- a US postal address on two lines is masked (street line, then City, ST 12345) (13bab17)
- a full name after a salutation is masked (Dear Dana Okafor,) (2d3f10b)
- a full name after a title is masked (Mr Dana Okafor, Mrs. …) (f07d52c)
- a Visa card number of 19 digits after a card word is masked (2822238)
- an ID after its label and a comma is masked (beneficiary number, <id>,) (bed99c3)
- a Markdown table of fields and values is read as one record (| Full Name | … |, one field per row) (5da6304)
- a North American phone number after calling, dial or contact is masked (8e4678e)
- an address after a Dutch, Swedish, Italian or German address label is masked (Adres, Adress, Indirizzo, Anschrift) (ceaaaea)
- a name after the Dutch and Swedish name labels naam and namn is masked (25ee85f)

## [0.7.2] - 2026-10-20

### Fixes

- a name after "first name is" or "last name is" in a sentence is masked (fffe655)
- a name in a declaration, a self-introduction or before its birth date is masked (I, <name>, hereby) (a7919ac)
- a double surname after a first or last name label is masked whole (Last Name: Okafor-Brandt) (7cacc49)
- a street after an address label is masked with its direction and unit (Main St SW, Oak Ave 12B) (8ee2e7f)

## [0.7.1] - 2026-10-20

### Fixes

- a double name that runs on into the next label is masked up to its surname (192d9b9)
- a double name is words only when it reads as words with and without its second surname (58d6ac6)
- a double name whose second part is a word and an address with a template after its unit are masked again (8011e44)

## [0.7.0] - 2026-10-20

### Features

- a library caller makes a rule of its own through user_rule, and LazyRegex is deprecated (52379f9)

### Fixes

- a street line under a hotel or company name stays text, and a small word starts no street (602360c)
- a European street line only widens a postcode another rule found, so a company address stays text (b9331c9)
- an address that a wider address hit already holds keeps that hit's rule (d01efc8)
- an address keeps the postcode, the city and the country after its street, and a European street line with postcode and city is masked whole (ae26485)
- an XML element that closes itself is read for its attributes too (aedd606)
- an XML element with a namespace prefix (fpml:party) is read as a record (3ebdbbd)
- an address or phone in a record nested right in a record that names a person is masked with it (51854a4)
- the attributes of an XML element (name, street_address) are read as a record like its child elements (87300e0)
- column and field names in German, French, Spanish, Italian, Dutch, Swedish and Portuguese name their values like the English ones (813553b)
- a column or field name with an XML namespace or a Markdown escape (fpml:name, first\_name) names its values like the plain name (8e42f33)
- personal fields of a JSON object and of an XML record are masked by the same column policy as a table (7419d4c)

## [0.6.44] - 2026-10-20

### Fixes

- an HTML table cell that wraps its text in a link or a span is read like a plain cell (dcb618b)
- personal columns of an SQL INSERT and of an HTML table are masked like those of a CSV file (7192858)

## [0.6.43] - 2026-10-20

### Fixes

- a phone extension after the number (x204, ext. 31) is masked with it (c72b82a)
- a medical license number is masked whole, not only the DEA-shaped part inside it (e88476b)
- an address after its label keeps the unit after Ste. or Apt. and the number after a short street name (1da20c3)

## [0.6.42] - 2026-10-20

### Fixes

- a double name with a hyphen is masked whole after its label, not only the part before the hyphen (4d8f40f)
- a driver license written in hyphenated groups is masked whole, not only its first four characters (25e65c9)
- a user name after the user name label in a sentence is masked in tool results, when it has a digit, a dot or an underscore (fe16811)

## [0.6.41] - 2026-10-20

### Fixes

- an id after its label with of, a certificate or license number, and an id with a letter prefix are masked whole (aaa81bb)
- the vCard parameters stay with BDAY when born on joins the birth labels (a742b84)
- a birth date after born on, or after date of birth with is or was, is masked in tool results (0c78760)
- a pull request or ticket number after the password word stays text (6897f3b)
- a password that ends with ! or ? is masked whole (197c4f1)
- a password with a letter, a digit and a sign after the password word is masked in tool results, also when it reads like a word (a7931d7)
- a card number written as one run of digits is masked in tool results when it has the prefix and length of a card network (49f9a1f)
- a number in a table column named account number is masked, wherever the table names it (8eeff23)
- an account number with a hyphen is masked whole, not only the digits after the hyphen (5d433ef)
- a US bank account number needs its label before it on its line, which removes a third of the false alarms in financial documents (2c134a1)
- masks Mastercard numbers of the 2-series and 15-digit JCB numbers, which the card rule never checked (27bf5fa)
- /maisecrets:status checks the Codex hook trust on Windows too, measured against Codex 0.164 (37d3392)

## [0.6.40] - 2026-10-19

### Features

- /maisecrets:status says whether Codex runs the maisecrets hooks of the installed version (b2df799)

### Fixes

- Codex users keep the hook trust they gave: apply_patch gets a PreToolUse group of its own (7cc1874)
- Codex 0.164 no longer switches the maisecrets hooks off after their first start on Windows (4d5d9f5)
- Codex apply_patch reaches the guard by its own name, also where a Codex build maps no alias (833ed2d)
- a birth date written YYYYMMDD after its label is masked (31e1676)
- an 8-digit date (YYYYMMDD) in a finance document is no US bank account number (af36b94)
- masks a user name after a username label, and a German tax id under a steuer_id key, in tool results (604d896)

## [0.6.39] - 2026-10-19

### Fixes

- detects the legacy Microsoft Teams webhook URL on outlook.office.com (e1914c0)
- a Microsoft Teams webhook URL is masked whole, not only 17 of its 204 characters (7dd7817)

## [0.6.38] - 2026-10-18

### Fixes

- an English word after a label in a tool result is masked only where it was found (c9128e1)

## [0.6.37] - 2026-10-17

### Fixes

- a person glued to a company's name keeps the postcode and VAT ID masked (dc42866)
- a config row stays text, and a folded END:VCARD does not end the card (e57a0e0)
- a person near a company keeps the postcode and VAT ID masked in the new forms (7822529)
- a company's postcode and VAT ID stay text in three more address forms (a405ecd)
- masks a vCard address, name or birth date in a line without its card (69fc9da)
- a vCard property folded over two lines is masked in both parts (469dafd)

## [0.6.36] - 2026-10-17

### Features

- the notice, the status and a refused call name the server's state and your next step (71028a9)

### Fixes

- a failed key change puts the old key back, and a late answer changes no state of a new key (fd443f5)
- a new key only for a key this computer holds, and state answers kept under the lock (cb39c27)

## [0.6.35] - 2026-10-17

### Features

- finds personal data in the person columns of a Markdown table (aa5384e)
- finds a street line after an address label or "resides at" (3d4b6e1)
- finds a first name or a last name alone after its label (e3374c1)
- finds a phone number in its national form after a phone word (af27a10)
- finds a passport or driving licence number after its label in eight EU languages (2f70512)
- finds an ID number after a health, tax or national label (e6d3a49)
- finds personal data and passwords after a label in Markdown bold (40ca2d9)

### Fixes

- placeholder streets, sentences after a name label and four-digit groups stay text (a1b76fd)
- the probe timer takes /bin/sleep before a sleep on the PATH (ce1f272)
- the probe bound holds when the client ignores a signal (ae7b354)
- a Python that hangs or holds the hook's output can no longer let a call through (54e799d)

## [0.6.34] - 2026-10-17

### Fixes

- ms:(…) keeps passwords with # < > as credentials and scrubs random letters alone (1453166)
- ms:(…) also stores random passwords with $, = or < in them, and judges each value alone (1ea083f)
- ms:(…) stores only a value that looks like a credential, and checks several values one by one (ef30391)

## [0.6.33] - 2026-10-17

### Features

- mask the values that your own tools found, also as a phrase of several words (814d942)
- Codex puts the values of a server's tokens into your files and commands (4cdaf8e)

### Fixes

- the marker patterns compile at the first prompt with "{{" (248e5a8)
- a PDF locked by a password is refused with that cause (f8b425e)
- a prompt with a template no longer loads the term matcher (4871bb5)
- a line continuation inside a word of an import removal is refused again (aee83ba)
- compile the patterns of the literal forms and of the keyword window at first use (406bf80)
- end every lock wait of a hook step at the step's deadline (8cdcc0d)
- read a long remote command in linear time (fc6dceb)
- search each rule keyword once per text (08523b4)
- read each vendored filter text once (8953366)
- leave out the CJK class when a text has no CJK letter (c81cc42)
- compile a module regex at its first use, not at import (69f4509)
- a removal of an import hidden by an escape inside a word is refused (d94bf79)
- a resumed Codex session never loses the answer of its start (655498d)
- a Codex session keeps the answer of its start, and the opt-out works at once (93f483d)
- a removal of an import that the shell joins from quotes or line ends is refused (d7f1fc8)
- a value file that is a symbolic link is refused on Windows too (77e1e22)
- an imported value in the text of a placeholder is masked, and only your setting makes a value file (6756514)
- a failed first run never lets the Codex header out later (22f9722)
- your value files keep their places, and no import can break a placeholder or a settings prompt (a604f30)
- the Codex header follows the folder the session began in (a867bba)

## [0.6.32] - 2026-10-17

### Features

- check a value with ms:(…) before you send it (0b3dde1)

### Fixes

- keep backups that maisecrets cannot prove it wrote (d7438f7)
- follow the client's file choice in the edge cases too (5521abb)
- use the config file that Claude Code itself reads (6cf98da)

## [0.6.31] - 2026-10-16

### Fixes

- a password after its word and a space is redacted, without the stop of the sentence (5096239)

## [0.6.30] - 2026-10-16

### Fixes

- on Windows the route for a document puts the value into a text file that the script reads (fa362f1)
- on Windows a refusal names the route that puts a value into a document (5dc8af7)

## [0.6.29] - 2026-10-16

### Features

- write the key header only for a server that sent a token and supports it (48ca94b)
- get a value back from the MCP server that masked it (42afa85)

### Fixes

- a token that the model sent before the server was in use is no sighting and no trigger (28fdfff)
- the header goes on the entry that sent the token, by name and URL (6ab449d)
- close the gaps that the fourth review found (538d4c6)
- close the gaps that the third review found (4e32659)
- a token seen again after 24 hours resolves again (d0f52cb)
- send the first sighting, so an old token never gets another person's value (87df6b0)
- close the gaps that the verification review found (f61ab37)
- close the gaps that the second review found (4b09970)
- close the gaps that the first review found (e7a66f5)

## [0.6.28] - 2026-10-16

### Fixes

- the document route of a deno refusal says deno run (fdb82d7)
- a refusal names the document route only where the rehydration setting lets it through (f3b9814)
- the skill tells the model how a placeholder goes into a document or a file (86c5ae4)
- when inline code cannot take a value, the refusal names the route to a document (dbabb47)

## [0.6.27] - 2026-10-16

### Features

- mask the names, case numbers and customer names on your own term list (1699c9d)

### Fixes

- review round 2 of the rebase: a listed value stored before stays a term, team lists are read with a bound (2f42ac3)
- review round 1 of the rebase: a union with a term stays a term, template braces mark no name (50a8b47)
- a wipe that cannot take the terms lock says what is left and how to finish (b21a092)
- a damaged marked-name record stops the hooks, and a wipe removes a proposal written at the same time (3c9bc9a)
- terms suggest never prints a name; it writes a private proposal file (41b9078)
- a team list cannot slow every hook with one stem repeated many times (ee0655b)
- a listed email address or token-shaped case number stays a term and is never resolved (a8ccc9b)
- term changes at the same time all hold; a damaged marked-name file stops the hooks; expired marks leave the disk (dd908a0)
- the refusal of an add without a source names the rule it broke in plain words (06229fa)
- term add masks the surname as a whole word, never as a stem; Codex adds follow your own rules (ebdd1e9)
- a token that holds a value you resolved is taken out whole again (88ad84c)
- the session start parses the term lists once (25bea54)
- an add from a prompt without a source gets the floor of a team list (ead02e6)
- a private-use character in a file the AI writes stays as it is (e5705e0)
- term add also masks the surname alone and joined names; typos and other origins change nothing (f1756ab)
- build the term index at session start and after a typed change, not inside a tool hook (27a1547)
- mask spaced *…* terms, overlapping names, NFD text, joined names and team lists safely (2a82c69)
- a listed name inside a stored password no longer leaves the rest of the password in clear (3f7c361)

## [0.6.26] - 2026-10-16

### Fixes

- a company's postcode and VAT ID stay text with its street (4cd8b0d)

## [0.6.25] - 2026-10-16

### Fixes

- masks a vCard address, name and birth date written in their fields, as contact exports write them (da3af5a)
- masks an encoded e-mail address in a CSV column named contact, login, username, recipient, courriel or correo (6e17722)
- masks the address, the name and the birth date of a vCard property with parameters, such as ADR;TYPE=home: (7af5ed4)

## [0.6.24] - 2026-10-16

### Features

- masks a card number written in groups in a tool result without a card word nearby, and knows more card words (cea3b1f)
- before reading a password export, a .har, a .vcf or an .ics file, the skill offers a masked copy and reads only that (94eb12e)
- judges a generic API key in a tool result by the entropy floor of its alphabet, which finds 8 more CredData credentials (d663062)
- finds personal data and secrets in 18 more fixed forms in tool results, such as an ID after "member", an address after "Address:", a FHIR identifier and a GitHub Actions ::add-mask:: value (44e2169)

### Fixes

- a busy machine no longer lets an encoded key through in a tool result (0f6c60f)
- after a password label, the name of a constant, a time such as 0:default, the word after "passed:" and a table cell of prose are no longer masked (07312aa)
- finds the counterparty IBAN in an MT940 bank statement export, right after its subfield code ?31 (c1215d3)
- a UK postcode alone is no longer masked, and a US NPI, a Swedish organisation number and a UK number plate need their check digit (1e6e78b)
- finds an e-mail address or a phone number written right next to Chinese, Japanese or Korean text (0889bbf)

## [0.6.23] - 2026-10-15

### Features

- decide what happens when the AI reads a PDF or an image, and send a PDF as masked text only (d599b5d)

### Fixes

- no hit in a converted PDF counts as a test fixture, also by its content, and a dangling rpath link counts twice (f13f774)
- a converted PDF under a tests folder keeps its labelled passwords masked (5a979a7)
- a missing rpath folder counts by the folder above it, and a converted PDF of one endless line says so (31c32aa)
- an inherited ACL entry on macOS and an rpath folder searched first also stop read_pdf convert (4569e77)
- read_pdf convert stops a PDF that eats memory, refuses a scan with page numbers, and runs a Homebrew pdftotext on a Mac with two admins (1d20371)

## [0.6.22] - 2026-10-15

### Features

- the session start counts your rules of your own and names a rule folder that is missing (d8c6993)
- add detection rules of your own from folders, and an allow list for single values (0f782bb)

### Fixes

- a rule of your own runs after the cleaned copy of a tool result, and the allow list holds for the personal-data rules (e0481e2)
- a rule of your own runs after the personal-data rules of 0.6.21 too, so it never cuts a name or an address (42f6cfd)
- a correct rule with several keywords is no longer timed out, and `rules check` makes a folder run at the next call (20c4a18)
- the folder limits also hold for refused, duplicate and oversized rules, and a slow branch is timed (0d3f4b0)
- a rule folder can no longer take out another folder's rule, run an untested rule, or stall a hook with many files (79a9dd4)
- a slow rule of your own is found by its own regex time, also over many strings (de45baa)
- a large output can no longer take a correct rule of your own out (4cc626a)
- rule folders keep slow, broken and linked rules out, and never print a refused line (923d3b2)
- a rule of your own no longer cuts an e-mail address, IBAN or phone number short (3772d16)
- a rule of your own that holds a hook until the watchdog answers is left out from the next call on (150e699)

## [0.6.21] - 2026-10-15

### Features

- the next session start names each protection that was loosened (e76fd95)
- a Twilio Account SID next to its name (TWILIO_ACCOUNT_SID, sid) is found (75adb3b)
- a Slack token with a shorter tail (xoxb-, xoxp-, xoxa-, …) is found (5c5be4b)
- an OpenAI or Anthropic key with a shorter tail (sk-proj-, sk-ant-, sk-svcacct-, sk-admin-) is found (bf4e532)
- the cells of a CSV column for personal data (address, dob, phone, ssn and a name beside them) are masked in a tool result (ecbb533)
- a name before an e-mail address ("First Last <mail>") is masked in a tool result (ba9f8e4)
- a name after a name label (patient, tenant, full_name, FN, Ansprechpartner) is masked in a tool result (d62d930)
- a street address with its postcode is masked in a tool result (US, UK, IN, DE, FR, PT, ES, IT forms by region) (e3adb4a)
- the user name in a home path of another person (/home/<user>/, C:\Users\<user>\) is masked in a tool result (d3acd12)
- the user name in user:password@host is masked in a tool result (7a83ec4)
- an ID number after its label (MRN, passport no, DL, SIN, TFN, NIR, tax id, account number) is masked in a tool result (91aaef0)
- a date after a birth label (DOB, Geburtsdatum, né le, fecha de nacimiento) is masked in a tool result (3c56393)

### Fixes

- a phone number with one-digit groups (+1 4 1 5 …) and a US number (312) 846-2291 after a phone word are masked (c2be01c)

### Security

- a prompt from a client that a program started changes no setting (0e50f95)

## [0.6.20] - 2026-10-15

### Features

- OpenAI and Anthropic keys of newer lengths (OpenAI: 8 to 400 characters around `T3BlbkFJ`; Anthropic: 60 to 140 before `AA`), GitLab trigger and CI job tokens in their newer forms are found without a label (18f35f1)
- 23 more token formats are found without a label (Google OAuth client secret, SonarQube, Dynatrace, NuGet, crates.io, Dropbox, GitHub App JWT, …) (7194cc0)
- a PEM private key in base64 is found and masked whole (Kubernetes Secret tls.key, ssh-privatekey) (c47bb41)

### Fixes

- a certificate bundle with a legacy encrypted private key in base64 is found (50742db)
- a base64 PEM key needs a key body, ends at its END line, and GitLab job tokens are taken whole (436069a)
- a routable GitLab token with a long routing payload is masked whole, not only its first part (98b4f30)
- Resend, Ionic, Airtable and WakaTime tokens are found without the provider's name beside them (768989d)

## [0.6.19] - 2026-10-15

### Features

- 25 more token formats are found without a label (Google OAuth, Claude Code OAuth, Tailscale, Discord, Telegram, …) (2787122)
- a crypto wallet seed phrase, private key or extended private key is a secret (9f54dea)
- Swiss and Austrian numbers with regions ch and at (AHV number, UID, social insurance number) (77fcc27)

### Fixes

- a PESEL, Spanish DNI or NIE, NHS, ABA routing number or codice fiscale with a wrong check digit is no longer a hit (a264b69)
- a Steuer-ID is checked by the tax office's own repeat rule and found with its spaces (88b80f4)
- a German ID card or passport number is found as the card prints it (f7a4868)

## [0.6.18] - 2026-10-14

### Features

- a password export in a tool result or a file is read without its passwords (589688b)
- tool results and files are also scanned without terminal and encoding disguises (56506c1)
- an IBAN written with hyphens or in lower case is found (28993c1)
- a card number next to "Karte", "carte", "carta" or "tarjeta" is found, not only next to "card" (8f256a8)

### Fixes

- a German VAT ID without a VAT word and a company register number are no longer masked (c6184b4)

### Other

- Merge branch 'feat/rules-from-the-fork' into 'main' (b0b681d)
- Merge branch 'docs/benchmarks-anyone-can-repeat' into 'main' (456c96b)

## [0.6.17] - 2026-10-14

### Fixes

- the word for "password" in another language stays text as a locale value in a tool result (af47b7e)
- the secret-hygiene scan reads files, commits and tool results as the tool hook does (0dbca9b)
- a word after a label in a tool result or a file no longer blocks later prompts; later tool results still mask it (945de68)
- a password of letters after a password label is redacted in tool results and files; a typed prompt keeps the rule of 0.6.16 (e0ee60c)

### Other

- Merge branch 'test/the-word-hunt-tests-use-the-fake-clipboard' into 'main' (3ea7c7b)
- Merge branch 'fix/tool-results-take-more-passwords' into 'main' (575827a)

## [0.6.16] - 2026-10-14

### Fixes

- the STS session token in X-Amz-Security-Token is redacted, also in a presigned URL (f3670a7)
- a password label before a long run of letters scans in linear time, 320 KB in 0.7 s instead of 10 s (721306e)
- a TOTP or HOTP seed after an otp, mfa or 2fa label is redacted (a46e38e)
- a key after a secret label is redacted in XML elements, calls and short values, also after hmac, session, cookie and psk (3da6b7a)
- the NTLM authenticate message, NATS nkey seeds, PASERK secret keys and PASETO tokens are redacted (9f2045d)
- a password after a password label is redacted when it looks random, also in XML, SQL and PowerShell; words, paths, references and measures stay text (74b851d)
- an Elasticsearch API key in an Authorization: ApiKey header is redacted (140c52c)
- each key in a list after a secret label is redacted, such as "api_keys": ["…", "…"] (ea4d655)

### Other

- Merge branch 'fix/more-labelled-keys-and-url-credentials' into 'main' (fe741d3)

## [0.6.15] - 2026-10-13

### Fixes

- one unusual betterleaks filter string can no longer switch off the whole ruleset (5237ca8)
- no helper tool can hold the session open, and an image output is checked to its last byte (8917315)
- a second curl -u or --user in the same command is redacted too (b6cee56)
- a tool result with stored values is redacted faster (d52521e)
- reading an image or a PDF is fast, and the shape check no longer damages the file (28b8137)
- on macOS and Linux a slow check now blocks the output instead of letting it through (f2c7b8e)
- a long line of AWS key ids or curl commands no longer stalls the check (1fa4fbc)
- finds passwords and tokens in a JSON object inside a string, such as {\"password\":\"…\"} (d159fb7)
- finds more passwords in commands and text: --password, mysql -p, Redis AUTH, .netrc and "my password is …" (32a729c)
- text with umlauts is judged by the betterleaks filters as betterleaks does (b95e8b4)

### Other

- Merge branch 'fix/0.6.15-detector-and-hook-time' into 'main' (85d7ca4)
- Merge branch 'refactor/the-kept-rules-are-maisecrets-own-rules' into 'main' (2d0b7d6)

## [0.6.14] - 2026-10-12

### Fixes

- faster scans: only the gitleaks rules that betterleaks lacks stay (7083dac)

### Other

- Merge branch 'fix/only-the-gitleaks-rules-betterleaks-lacks-stay' into 'main' (b3c7473)

## [0.6.13] - 2026-10-12

### Features

- secrets of about 200 more services, from betterleaks instead of gitleaks (baf8e64)

### Other

- Merge branch 'feat/18-the-detector-uses-the-betterleaks-rules' into 'main' (4859e60)

## [0.6.12] - 2026-10-12

### Fixes

- the review of the #16 change: pipes, paths after a run verb, values after an option (ae39418)
- the consent check reads the low findings left from #15 (bea15d5)
- a test value hides only its own type, and %40 needs an address context (fb771c3)
- a test value counts only for its own type, and %40 only where an address is expected (b16d6e6)
- documented test values, percent-encoded emails and invalid SSNs (6432d2c)

### Other

- Merge branch 'fix/detector-gaps-from-public-benchmark' into 'main' (b7806b2)

## [0.6.11] - 2026-10-10

### Features

- consent-report shows what the ssh consent check would ask on your own sessions (2ea0184)

### Fixes

- the consent check reads a package manager's exec, long xargs options and a find -exec clause (f757dc6)
- the consent check reads a here-string into a shell, a trap's code and env -S (c018436)
- the consent check reads a session name, a -- and a URL option where they stand, and fish code glued to its option (c5f7d22)
- the consent check finds a container's program by its place and a program path by its directory (8d6dc0e)
- the consent check reads a shell's arguments, a container's inner command and a launcher's program (a16f23f)
- the consent check reads a container command, a continued argument list and AppleScript the way the shell does (60f58c3)
- the consent check sees ssh as a path, after an escape and in fish or AppleScript code, and no longer after a substitution in an argument (291ce37)
- consent-report names no host in a reason, and the check reads a few more launchers and lookups (034c520)
- the consent check reads launchers past their flags and stops asking for a daemon, a package or a file named like ssh (d822281)
- the consent check asks for a launcher or a subcommand it does not know, and no longer for git's option words in a message (7da266c)
- the ssh consent check asks where a command starts ssh, not where a command mentions it (9a04d72)

### Other

- Merge branch 'fix/c21-asks-on-visible-executable-intent' into 'main' (b06ab19)

## [0.6.10] - 2026-10-09

### Breaking

- no report form opens a browser or runs gh; the person files the issue in GitHub's form (4c91c53)

### Features

- every failure site records its code, and the launchers and the guard leave markers (4703c64)
- /maisecrets:report incident shows the report to the person, also with a damaged store (327ef52)
- hooks record their failures after the answer, and the hook always ends in time (5a53a88)
- a local incident record with closed values, markers that follow nothing, and a report that sends nothing (3f908c0)

### Fixes

- without Python, run.cmd refuses every hook event in JSON with exit 0, so Codex no longer runs the tool (7e98099)
- clear returns the plugin marker it removed also when the home cannot be listed (dd5e7b7)
- run.cmd leaves its marker in its own hooks folder, with no child and no touch of the home (dc8d7b5)
- run.cmd makes its marker in a detached child, so a stalled home cannot hold the hook (38fb21c)
- code review round 1 - a winning watchdog writes no heartbeat before its exit, and markers never hold a hook (4f07b23)
- one layer against a symlinked record, so its test can fail (c5617e8)

### Security

- a home the hook cannot search no longer lets a prompt through on Python 3.9 (e45ab0a)

### Other

- Merge branch 'feat/local-diagnostics-build' into 'main' (5c79d73)

## [0.6.9] - 2026-10-08

### Features

- the caps on stored values are 200 per session and 1000 uses an hour, and you can raise them (493cf77)

### Fixes

- the mod's tries share one budget on the mods clock, and a test holds it; README and PRIVACY name every connection (26a2482)
- the mod tries the next Python after an error exit too, within one 8 s budget; review round 1 of 0.6.9 (07fafe6)
- the mod starts the plugin's Python with fixed arguments, without a shell or an environment read (0eec13d)

### Other

- Merge branch 'feat/limits-from-the-logs' into 'main' (8485966)

## [0.6.8] - 2026-10-08

### Fixes

- a URL password that looks like a date counts as a date only if the calendar has it (3a46fc3)
- the SigV4 scope ends at a separator; a URL password filter takes only a whole reference or a real date (567a1d5)
- only a whole encoded reference or date in a URL password is text; the SigV4 scope must end at aws4_request (14b3402)
- the end of a call commits only its own session and agent, however late; a failed call carries its hint (e68c7b7)
- a password with no user in a URL is found (redis://:password@host) (282281e)
- the AWS key id in a presigned URL or a SigV4 header is no secret (ebec40b)
- a destination is seen only after the call ran; a declined call leaves no record (04f268b)

### Other

- Merge branch 'fix/seen-only-after-the-call' into 'main' (6ae1b4d)

## [0.6.7] - 2026-10-08

### Features

- maisecrets notes where each stored secret was sent, and /maisecrets:list shows it (dd74bc9)

### Fixes

- a file label uses / on Windows, and only the home folder itself becomes ~ (cc1ee66)
- a heredoc after a parenthesis, any carriage return, and $ in double quotes ask (review round 7) (adb691e)
- an ssh word in a comment the shell may not read as one asks; the parser stays as in 0.6.6 (review round 6) (0de44da)
- a # or << inside (( )), $[ ], [[ ]] or ${ } is no comment and no heredoc (review round 5) (d6c3339)
- read -v from the dequoted words (review round 5) (aa05dc4)
- escaped space before # and printf -v ask; a record goes when its value expires (review round 4) (3120795)
- text exemption only for a line that runs nothing else (review round 3) (b335e82)
- ssh text rule only for quoted text, destination record bounded (review round 2) (204d745)
- review round 1 of 0.6.7 (codex): text that a later part runs stays an ssh call; observing never waits (9e7d60f)
- the word ssh in text (an issue body, a grep pattern) no longer asks (25778ab)
- /maisecrets:settings ssh_autonomous_hosts add HOST shows the card instead of an error (dff5443)

### Other

- Merge branch 'feat/secret-destinations-observe' into 'main' (0760a76)

## [0.6.6] - 2026-10-07

### Features

- autonomous hosts, where the AI may change things over ssh without asking in every session (df1680c)
- a value in the output of a failed call is stored, cleaned from the transcript and named to the AI (16ae737)
- the settings read as cards with the next command, a change shows its result, and hints can be reset (fcf41dc)

### Fixes

- a group name in the autonomous hosts stands for its members only; the failed-output message says when cleaning failed (dafba9b)
- the failed-output message says what was stored and whether the transcript is cleaned (7a70dfe)
- a command that calls a consent writer by name is refused, and a wrong Codex sentence ends the code (18c1ef4)
- with ssh_consent on, a yes allows only the asked command; a host window opens only from your own prompt (8be6a89)

### Other

- Merge branch 'feat/settings-ux-ssh-per-command' into 'main' (26b7252)

## [0.6.5] - 2026-10-07

### Features

- /maisecrets:settings shows what you decide, and a hint names ssh_consent once (f137459)

### Fixes

- an sdk prompt changes no setting, since a program a tool started can send one (09a02c3)
- only a prompt the person typed changes a setting, and the hint comes once under parallel hooks (3694cf8)

### Other

- Merge branch 'feat/settings-and-hints' into 'main' (1fdb482)

## [0.6.4] - 2026-10-07

### Features

- with ssh_consent on, a write over ssh asks once per host, a read runs (c0c768d)

### Fixes

- the guard reads the switch of the copies that are installed, by their exact ids (codex review) (97b6950)
- a second maisecrets copy switched off no longer silences the guard (1121958)
- command names in any case, a size cap that answers in time (opus review, round 3) (7ba4ed8)
- ~/.ssh is guarded by a list of reads, not of writers (codex review, round 3) (f6daea9)
- the deny list and the ~/.ssh rule read the whole command (opus review of the repair) (6368ed8)
- redirects are read from the raw text, mosh and rsync ports keep the host key (codex review of the repair) (2a3cbad)
- consent keys follow ssh's first value, and the hidden targets ask (opus review) (ff33819)
- consent keys carry user and port, forwards and content reads are writes (codex review) (9522730)

### Other

- Merge branch 'feat/8-every-ssh-command-can-ask-first' into 'main' (cdfd065)

## [0.6.3] - 2026-10-06

### Fixes

- a bot or pipeline mailbox at .local or .internal is no longer taken for a person (3e93c8e)

### Other

- Merge branch 'ci/renovate-keeps-the-vendored-rulesets-current' into 'main' (29e6a1a)

## [0.6.2] - 2026-10-06

### Features

- invisible characters that can carry hidden instructions leave tool results (6f548b3)

### Fixes

- a routable GitLab token is detected whole, its tail no longer stays in the clear (a22e142)
- a prompt the hook blocks because it cannot finish no longer stays in the transcript (1be2b04)

### Other

- Merge branch 'feat/invisible-characters-a-failed-hook-scrub-and-routable-tokens' into 'main' (25ab1cb)

## [0.6.1] - 2026-10-06

### Fixes

- the mod runs a fixed command line, lives in its own folder, and the README says what it sends (e458172)

### Other

- Merge branch 'fix/the-mod-says-what-it-runs-and-lives-apart' into 'main' (3985709)
- Merge branch 'test/the-replaced-file-test-holds-on-windows' into 'main' (3e2e7d5)

## [0.6.0] - 2026-10-06

### Features

- a prompt with a secret goes through with placeholders on Claude Code with mods (7eef69d)

### Other

- Merge branch 'chore/the-mod-answer-is-ascii-json' into 'main' (d079c7d)
- Merge branch 'docs/an-agent-checks-the-upstream-changes-that-change-the-design' into 'main' (bd17a6d)
- Merge branch 'test/the-release-tests-ignore-an-approved-bump-in-the-ci' into 'main' (9a3c46e)
- Merge branch 'feat/a-prompt-with-a-secret-is-rewritten-not-blocked' into 'main' (fade6ff)

## [0.5.24] - 2026-10-05

### Fixes

- a command that runs as the Codex sandbox user leaves the store alone (29285b8)
- a permission failure names the likely causes, and the run log names the file (58e9bd9)
- leave the skill's Codex metadata out of the release branch (d6dd769)
- leave the Codex manifest out of the release branch (3734aca)
- a hook that may not write its store names the cause and the way out (ee08ba6)

### Other

- Merge branch 'fix/windows-sandbox-user-home' into 'main' (2a89caa)

## [0.5.23] - 2026-09-30

### Fixes

- hooks work when the client clears their environment (f43af3e)

### Other

- Merge branch 'fix/run-cmd-cleared-env' into 'main' (31ac4ac)

## [0.5.22] - 2026-09-30

### Fixes

- run.cmd records each start, so a hook that does not act can be traced (e87c522)

### Other

- Merge branch 'fix/run-cmd-last-start' into 'main' (19a19a8)

## [0.5.21] - 2026-09-30

### Fixes

- a command in the Windows sandbox names its cause and runs again outside it (9590ae4)

### Other

- Merge branch 'fix/commands-in-codex-sandbox' into 'main' (d638070)

## [0.5.20] - 2026-09-30

### Fixes

- name the Python install for all users in every hint (e895d25)

### Other

- Merge branch 'docs/windows-codex-learnings' into 'main' (33f3e59)

## [0.5.19] - 2026-09-30

### Fixes

- find Python in its install folder when it is not on PATH (21f0d65)

### Other

- Merge branch 'fix/find-installed-python' into 'main' (35e1b45)

## [0.5.18] - 2026-09-30

### Fixes

- find the plugin folder when Codex on Windows sets no CLAUDE_PLUGIN_ROOT (edf787a)

### Other

- Merge branch 'fix/codex-plugin-folder' into 'main' (5eec0fe)

## [0.5.17] - 2026-09-30

### Fixes

- ship hooks that name one program on the release branch (d307228)
- name a PowerShell form for Windows without bash (f02419a)

### Other

- Merge branch 'fix/commands-on-windows' into 'main' (efba65c)

## [0.5.16] - 2026-09-30

- **The Claude plugin directory accepts the hooks again.** It refused 0.5.15 because the PowerShell
  part of each hook started `hooks/run.cmd` from a variable; the directory wants every program named
  by its path. The hooks now name `${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd` directly. Nothing changes in
  what they do.

### Fixes

- the Claude plugin directory accepts the hooks again (70e73df)

### Other

- Merge branch 'fix/directory-spell-the-program' into 'main' (8d1a65e)

## [0.5.15] - 2026-09-30

- **Codex on Windows: a removed plugin folder now blocks instead of letting the tool run.** Codex
  removes the folder of the old version when it installs a new one, also under an open session
  (codex-cli 0.159.0, measured). The Windows command of each hook (`commandWindows`, run by
  `cmd.exe`) now checks for the launcher first and answers with a block when it is gone, as the
  macOS and Linux command already did. The text tells Codex users to exit and run `codex resume`
  instead of a Claude Code command.

- **Code after a colon is no longer stored as a secret.** A line such as `if not token: <statement>`
  put the statement word into the vault, and maisecrets then redacted that word in every later text,
  in source code too. A statement keyword after a label (`break`, `return`, `pass`, `raise`, …) is not
  a value now; so a password that is exactly such a word is not stored either. One lowercase word after a label, with
  the sentence going on, is still stored: without a dictionary it looks like a password of letters,
  and a missed password costs more than a false positive.

- **The false positives of the old detector stop at the next session start.** A statement word
  such as `return` that an earlier version stored after a label stayed in the vault until it
  expired, and maisecrets redacted it in every text until then. The session start now marks these
  entries so that maisecrets no longer redacts the word in other texts, and names their keys once.
  Nothing is deleted: the placeholder still works, and `/maisecrets:forget` deletes the entry. The
  start finds them by fingerprint and reads no stored value. The same word stored by
  `/maisecrets:put` or another rule stays as it is.

- **A subagent's report no longer stops the session.** When a subagent quoted a value in the shape of
  a secret, its report reached the session as a prompt, and maisecrets blocked it until you pressed
  Cmd+V or `/ms`. A model of this session wrote that text, so the block protected nothing. The report
  now passes when it proves itself against the files of this session: the call that started the
  subagent, the subagent's own transcript, and its last answer. A value that anyone added outside the
  answer still blocks. `"pass_agent_reports": false` in `~/.maisecrets/config.json` turns this off.

- **Fewer false alarms in source code.** A run over the Python standard library (36.6 MB, no real
  secret in it) found 38 "secrets", 666 "IP addresses of a person" and 26 "phone numbers". These are
  no longer hits: a name on the right side of an assignment (`authkey=authkey`, `self.token = nextchar`,
  `TOKEN_ENDS = TSPECIALS | WSP`), a word of an error message (`pwd: expected bytes`), a format string,
  a time zone (`key = "Europe/Dublin"`), a mask (`*******`), a signed number in code (`a = +4294967296`),
  a number with more than 15 digits, and the documentation, shared, reserved and multicast address
  ranges and the public DNS resolvers. A quoted value, a value in a properties file and a phone
  number in prose are still found.

- **Test passwords no longer stop the work.** A password that maisecrets finds only by its label
  (`password = '…'`) is a fixture in test code: in a file on a test path, in a grep line of a test
  file, or after a test marker such as `def test_`, `assert` or `describe(`. A pasted unit test now
  passes, and a Read of a test file keeps its fixtures. A token shape (`glpat-`, `AKIA`, a JWT, a
  private key) and personal data are still found in test code, also after a label such as
  `token = "…"`. An `.env` file and a recorded HTTP cassette are no test code, even under `tests/`,
  and `assert` alone does not make production code a test.

- **Fewer false alarms in config, docs and code.** A review of 679 snippets of normal work and a run
  over a real repository found more values that are no secret, and these are no hits now:
  - fixtures that name themselves (`testpass`, `secret123`, `Passw0rd!`) and a default that equals
    its label or user (`POSTGRES_PASSWORD: postgres`, `curl -u admin:admin`). A real password that
    holds such a word and a word of its own (`Contest-Winter2026!`, `Passion2026!`) is still found
  - the next label of an `.env.example` (`DB_PASSWORD=` followed by `API_KEY=`)
  - types (`Option<String>`, `list[str]`), templates (`mcp_{user}`, `?token={id}`), version pins
    (`tokenizers==0.20.3`), durations (`TTL_REFRESH_TOKEN = 15552000`), UUIDs, elided values
    (`sk-...`) and labels of a derived thing (`secret_name`, `password_hash`)
  - e-mail addresses at `example.com`, `.test`, `.invalid` and `.localhost`, and a system mailbox at
    `.local` or `.internal` (a person's name there, such as `hans.mueller@firma.local`, is still
    found), and section numbers such as `RFC 6749 4.1.2.1`
  - YAML anchors, shell expansions such as `${REDIS_PASSWORD:?…}`, a type made of the words of its
    label (`token_data: TokenData`) and a command with a path
  In the tests of that repository, the label-rule hits that a Read acted on went from 379 to none.
  The example on the first start is now an address that maisecrets stops.

- **A word no longer follows you around for a day.** When maisecrets found a word such as
  `postgres` only by its label (`DB_PASSWORD=postgres`), it stored it and then redacted the word in
  every later text of every session: `docker ps` showed a placeholder for the image, and the prompt
  "add a postgres service" was blocked. Such a word is now replaced where it was found and nowhere
  else; its placeholder still works. This holds for the default words of services and of code
  (`postgres`, `admin`, `redis`, `changeme`, `plaintext` …); any other value, also a random
  lower-case one, is still found everywhere.
  Words that an older version stored are marked at the next session start.

- **A busy computer no longer ends a session.** When maisecrets answered a call too late, the guard
  said to exit the session and resume it, and an agent that worked on its own stopped there for a
  person. The next call would have worked. The guard now says to run the call again, and names the
  restart only as the second step; when maisecrets started and was only slow, it names no restart.
  After a plugin update, which the guard sees in the trash, it asks for the restart as before.

### Features

- a reported false alarm links the test data that maisecrets leaves alone (f3f2ead)

### Fixes

- a subagent's report passes on Windows too (fbb2d34)
- a password that starts with & or ! is no YAML anchor, and many hits stay linear (c674527)
- the scan is linear in a long line, and the review of 3e5d53e is closed (b4a7c54)
- a long line is scanned in time again, and the final review's findings are closed (3e5d53e)
- tel inside a word is no telephone label (0147e81)
- the second Codex review of 05052fe found eight more; each is closed (37a68a8)
- the Codex review of 31fdfd1 found seven more ways through; each is closed (05052fe)
- no relaxation of this release lets a real, detectable value through (31fdfd1)
- a busy computer no longer ends a session (50468d0)
- a real subagent report is no longer blocked by its own shape (ba63f17)
- a word no longer follows you around for a day (6a9162f)
- fewer false alarms in config, docs and code (c33271b)
- test passwords no longer stop the work (edd6df0)
- fewer false alarms in source code (86d56e8)
- a subagent's report no longer stops the session (fbbe7c5)
- the session start deletes the code words an older detector stored (5757d20)
- the review of the detector and the Windows fallback (d805b1e)
- Codex on Windows blocks when the plugin folder is gone (28c64d0)
- code after a colon is not a secret value (aa79eab)

### Other

- Merge branch 'feat/agent-reports' into 'main' (aa639a4)

## [0.5.14] - 2026-09-29

- **The restart command stands on a line of its own** in the refusal of the guard, so it is easy to
  see, and a triple click copies just that line. The refusal now says the command *was* copied to
  your clipboard: a terminal with copy-on-select (the default in Ghostty) replaces the clipboard as
  soon as you select text, also text in the refusal itself.

### Fixes

- the restart command stands on its own line; the refusal says it was copied (3fef4b4)

### Other

- Merge branch 'fix/guard-message-layout' into 'main' (0d17b8b)

## [0.5.13] - 2026-09-29

- **Synced installs: the guard now gives the restart command.** After a synced update,
  `/reload-plugins` can keep the path of the gone plugin folder (anthropics/claude-code#97847), and
  then it cannot load maisecrets again. The refusal of the guard now says so and names the command
  that works: exit, then `claude --resume <id of this session>` in the directory where the session
  started. Run `/maisecrets:guard install` once more if you installed the guard yourself.
- **The guard puts that command on your clipboard**, once per session (`pbcopy` on macOS, `clip` on
  Windows, `wl-copy`, `xclip` or `xsel` on Linux). Exit, paste, press Enter. The refusal says so only
  when the copy worked. `MAISECRETS_GUARD_CLIPBOARD=off` turns it off.

### Features

- the resume command goes to the clipboard, once per session (857be68)

### Fixes

- the refusal gives the restart command when /reload-plugins cannot help (7f1292e)

### Other

- Merge branch 'fix/guard-restart-hint' into 'main' (8f58a86)

## [0.5.12] - 2026-09-29

- **Windows without Git Bash: maisecrets now protects Claude Code there.** Claude Code runs a hook
  command in PowerShell when Git for Windows is not installed. The hook commands of 0.5.11 were bash
  only: PowerShell refused to parse them, the hook failed without a block, and a prompt with a secret
  reached the model. Each hook command now works in bash and in PowerShell. The `PowerShell` tool of
  Claude Code meets the store guard, and a placeholder in a PowerShell command is refused with the
  reason.
- **A guard you installed yourself** (`/maisecrets:guard install`, not a synced install) keeps the tool
  list of its version. Run `/maisecrets:guard install` once more after this update, so that it also
  covers the `PowerShell` tool.
- **Codex users: re-trust the hooks once in `/hooks` after this update.** `hooks/hooks.json` changed.
  Until the hooks are trusted again, Codex runs no maisecrets hook and says nothing.

### Fixes

- refusals name what works without Git Bash; the PowerShell part has a test (2920339)
- the store guard knows the Credential Locker listing, the launchers' get and two Windows spellings (a2023ac)
- maisecrets protects Claude Code on Windows without Git Bash (8ad4795)
- every generation of the synced folder counts; the guard's own refusal names it (f979433)

### Other

- Merge branch 'feat/windows-powershell' into 'main' (83ba31b)

## [0.5.11] - 2026-09-29

- **Synced installs: a guard against the update gap, set up by maisecrets itself.** An update of a
  plugin that the organisation syncs from claude.ai can leave a session without maisecrets, silently.
  At its next session start a synced maisecrets places `~/.claude/maisecrets-guard.py` and registers
  it once in `~/.claude/settings.json` (a backup first, only the hooks change, one line says so). The
  guard blocks a prompt or tool call that maisecrets did not answer and names `/reload-plugins`.
  `/maisecrets:guard remove` takes it away; `"guard": false` in the config or the machine policy
  keeps it off. Installs from the marketplace and Codex are not touched.
- **Codex:** a placeholder in a file edit (`apply_patch`) is now resolved, and a patch against the
  maisecrets store is refused.

### Features

- a guard outside the plugin folder stops a session in which an update left maisecrets not running (4cdbdcd)

### Fixes

- "guard": false works without a guard.json; a person's --off stays their own (72eef2d)
- a multi-line value stays file content in a Codex patch; the guard waits for the answer (8d28b90)
- the update window reads the change time; the measured folder counts per account (8e7b4cc)
- no lasting block after an organisation removes maisecrets; the script is guarded too (c02e964)
- a patch header behind any whitespace is a header; the guard expects by account (3a158d4)
- two registrations pass a healthy call; an indented Codex patch header is a header (5af2899)
- Codex apply_patch resolves a placeholder and never writes the maisecrets store (5f3a399)

### Other

- Merge branch 'fix/guard-windows-tests' into 'main' (3c998cd)
- Merge branch 'feat/codex-apply-patch' into 'main' (746374c)

## [0.5.10] - 2026-09-29

- **Behaviour change: maisecrets adds no approval of its own by default.** A value still never
  reaches the model, and a form where it could turn into code is still refused. What changed: an
  MCP call and an ssh command that get a real value no longer ask first, and on Codex a value in a
  published-text field (`text`, `message`, `body` …) now goes in. In Claude Code your permission
  rules decide, as for any other call; in Codex maisecrets answers `allow`, as it did for Bash and
  for other MCP fields, and Codex's sandbox and MCP tool approval still apply. To keep the ask of
  0.5.9 for MCP and ssh, set `"rehydration": "confirm"` in `~/.maisecrets/config.json` or in the
  machine policy. `confirm` is stricter than 0.5.9 on the other paths: Bash and Write/Edit ask too,
  and Codex refuses every rehydration, because it cannot ask. `"block"` turns rehydration off.
- **For administrators:** a machine policy file that exists but cannot be read now makes the hooks
  fail closed (before, it counted as no policy). Keep it and its folder readable by every user. A
  key in it that looks like a misspelled `rehydration`, `resolve_in_files` or `ssh_via_sandbox`
  blocks rehydration until it is fixed; other unknown keys are ignored with a warning.

### Features

- maisecrets adds no approval of its own by default; rehydration confirm and block are optional (9eead0c)

### Fixes

- the limiter answers an empty key list without an index error (82264ef)
- a lowered key cap no longer breaks a call with known keys (9725364)
- a misspelled safety key blocks even next to a valid setting; caps count per call (650167c)
- a setting that cannot be read as written blocks rehydration; no partial resolve (cdb57a8)
- an ignored config file never loosens the rehydration policy (a043a33)

### Other

- Merge branch 'feat/rehydration-policy' into 'main' (b945f23)

## [0.5.9] - 2026-09-28

- **Codex:** `hooks/hooks.json` changed in this release, so Codex asks once in `/hooks` to trust
  the hooks again.

### Features

- sudo -n before a read-only remote command counts as read-only (a1711d2)
- Norwegian and Czech credential labels, regions no and cz (85a8649)
- Portuguese and Danish credential labels, regions pt, br and dk (161762c)
- French and Dutch credential labels, regions fr, lu, be and nl (b7da1cf)
- Korean and Thai credential labels (6cff625)
- Polish and Turkish credential labels (46d578e)
- Finnish and Swedish credential labels (02c2f1b)
- Spanish and Italian credential labels (1b2ca9c)

### Fixes

- the context window is cut from the original text, then lowered (1d2918c)
- Turkish labels in capitals, such as ŞİFRE: (ce1aef5)
- a refusal about the store says what the user does next (1aad280)
- a second hop names one ssh per host; the sandbox e2e runs an ops user's forms (e64bec6)
- a false-positive report names the forget command and deletes nothing itself (6a1ea89)
- a refusal names the form that works, and the primer says what to do (e5f806a)
- /ms sends the blocked prompt of its own session, also when two sessions wait (f90cc47)
- a hook command that finds no launcher refuses; Claude Code still skips a moved plugin (f6b2cb8)
- a space before the colon of a label, as French typography writes it (a8fad39)

### Security

- every fail-closed answer has the shape of the client that asked (481810d)
- a hook that cannot work refuses in JSON, which Codex reads too (12b8400)
- a session id is a name, never a path, and a command cannot set it (e1bae80)
- an entry point that cannot import the plugin's code refuses instead of passing (1793d1c)
- an MCP resource read that names the store is refused (fd2e23a)

### Other

- Merge branch 'fix/i2-windows-form' into 'main' (287f6d2)
- Merge branch 'feat/label-languages-l10n' into 'main' (69a4d9d)
- Merge branch 'ci/faster-matrix-and-prepush-scan' into 'main' (fbd732a)

## [0.5.8] - 2026-09-28

### Fixes

- recognise a Windows file URI that names the store (3cca981)
- name an unknown key only when it is a typo of a real one (55f491f)
- catch a value JSON-escaped twice in an MCP result (3e46e48)

### Security

- catch another session's value that a command printed as hex or base64 (431ad59)
- refuse a hard link, a file URI and a configured home path into the store (356bbfc)
- block a prompt that carries a value the store already holds (fabbd5f)

### Other

- Merge branch 'fix/windows-invariant-paths' into 'main' (21d9ff5)
- Merge branch 'feat/invariant-beliefs' into 'main' (ad2711b)

## [0.5.7] - 2026-09-28

### Fixes

- the transcript scrub opens the file in binary mode on Windows (c1a8b56)
- Grep without a path, Windows digit scrub, Unicode word boundary (4aa1eb6)
- the Codex review of the read gate, short values and the digit scrub (e07b32f)
- a detected value of only digits is scrubbed from the transcript (8f537bd)
- Read, Grep and Glob never read the store (96f92f3)
- a short value the session put in comes back masked (1d8cfa3)
- the ssh route works in the Linux sandbox (335ee7c)

### Other

- Merge branch 'fix/windows-binary-scrub' into 'main' (2301d89)
- Merge branch 'fix/linux-sandbox-proxy-login' into 'main' (46a3b62)

## [0.5.6] - 2026-09-28

### Features

- ssh_approval per-session, one approval per value and session (e0b9bc3)

### Fixes

- journalctl --synchronize-on-exit is not read-only (bcd1a4a)
- the sealed directory stays sealed; stateful commands leave the read-only list (150dc88)
- the Codex review of the ssh session approval (be8be6a)

### Other

- Merge branch 'feat/ssh-session-approval' into 'main' (78f0e8c)

## [0.5.5] - 2026-09-28

### Fixes

- a plugin linter; the report frontmatter parses as YAML again (d2ad842)
- the shell rule counts only input and traces that reach the shell (c85b8a4)

### Other

- Merge branch 'fix/shell-rule-scope' into 'main' (f0c5ca0)

## [0.5.4] - 2026-09-28

### Features

- run on Python 3.9, the stock python3 of macOS (d4a95b9)

### Fixes

- the second Codex round, shell input and trace settings anywhere (41e3978)
- four findings from the Codex review of the 0.5.3 follow-ups (9964898)
- four points from testing 0.5.2 (encoder rule, arguments, browser, report) (16881b6)
- env -S in its real words, and a backslash-newline joins the line (2ebd713)

### Other

- Merge branch 'fix/tests-under-xdist' into 'main' (465df55)

## [0.5.3] - 2026-09-28

### Features

- ssh gets a value on stdin inside the Claude Code sandbox, after a confirm (8eb8e5a)

### Fixes

- the final review follow-ups for the ssh route (2d434e2)
- the final review of the ssh route and the command-word rules (54889dd)
- the ssh safety net no longer refuses a sentence or a part without a value (7e1004d)
- the ssh options follow the command word, past wrapper option arguments (9015378)
- ssh in any other form is refused, and the guard checks the proxy (4b11421)
- the second review round of the ssh route (341f7d2)
- a command word hidden by quotes, a variable or a runner is still checked (985ff2a)
- the ssh route reads options after the host and the whole remote command (dee6b85)
- the ssh route also switches off shared ssh connections (a814d85)
- a short value glued to its label is a value (65bd51e)

### Other

- Merge branch 'feat/ssh-through-the-sandbox' into 'main' (dc08fbd)

## [0.5.2] - 2026-09-27

### Features

- each release also goes to a GitHub branch with only the runtime files (4554787)
- no install offer where no agent CLI exists (a web or mobile chat) (0d7dbfb)
- every task starts with a protection check, and the skill installs the hooks after a yes (0b241fb)

### Fixes

- the release tree builder passes NUL-separated bytes to git (2294a44)
- the release tree builder uses the release identity when git has none (93f1b9b)
- the hook waits for its watchdog thread before it ends (7c4c63f)
- the zip folders can be opened, and the offer text comes with the verdict (00c909a)
- the protection check follows this agent's own hook run, and the offer asks first (6a50c95)

### Other

- Merge branch 'fix/release-tree-binary-on-windows' into 'main' (00eda11)
- Merge branch 'fix/hook-waits-for-its-watchdog' into 'main' (e9c7762)
- Merge branch 'feat/skill-installs-the-protection-2' into 'main' (a74d9d8)

## [0.5.1] - 2026-09-27

### Features

- label languages as data files and regions from the system setting (46a7d5a)
- the first session start says how to try maisecrets (9a40916)

### Fixes

- expire counts only the values it deleted (a4c23b2)
- the commit before a release goes to the GitHub branch ci, not main (349da5e)
- a release moves only the last number; a higher one needs approval (e92e7ab)

### Other

- Merge branch 'fix/release-bumps-only-the-patch' into 'main' (ac124b6)

## [0.5.0] - 2026-09-27

### Breaking

- a breaking change of a silent type is listed under Breaking (ab8927d)

### Features

- pass and token are labels, a value may start with a symbol, the matrix is a gate; fix(ci): the repo scan checks each file and its own exit code (5168298)

### Fixes

- the skip gate accepts the native clipboard test (c681f9b)
- clip gets UTF-16 without a byte order mark (c5658b7)
- a placeholder word inside a random token is chance (daea5bb)
- read the clipboard without a byte order mark (adf4b59)
- the clipboard keeps ⟦ ⟧, and the tests never reach the real clipboard (990c45c)
- the unit and beliefs jobs install procps for ps (77f10b6)
- status closes the files it reads (5370e91)
- repair never gives a new value the key of an old placeholder (0bf9d0a)
- get refuses an entry past its expiry that the sweep has not purged (86bfca7)
- a value-serving child ends when its FIFO is taken back (ba1197b)
- a file store that refuses is reported, never a traceback (f96bead)
- wipe --yes deletes hooks.log as the notice says (a967d0d)
- a prefix-only IPv6 address no longer shows whole (b962e32)
- a gitleaks "match" allowlist sees the whole match (8f9bbfb)
- the keyword window ends one line too early (860ba9e)
- two distinct characters after a label are a value (178ebb1)
- an unquoted value after a label ends at the first whitespace (17603ad)
- a dotted reference after a credential label is not a value (51dde31)
- a store call that times out raises RuntimeError without the argv (d8f28f0)
- a stored value that comes back URL-encoded or JSON-escaped is replaced (c36fdef)
- a damaged vault index withholds the tool output instead of passing it raw (3e8e971)
- a payload that is JSON but no object is blocked instead of let through (c23f154)
- release the lock when the index read inside a mutation raises (de86fb5)
- a policy file that is not one JSON object fails closed (9ebcd60)
- CLI and session start print a traceback on a damaged index or a bad policy (5af6016)

### Other

- Merge branch 'fix/windows-tests' into 'main' (822d85f)
- Merge branch 'test/broad-coverage' into 'main' (3927b78)
- Merge branch 'worktree-agent-ad7d100b64b11e581' into test/broad-coverage (81b1370)
- Merge branch 'test/detection-matrix' into test/broad-coverage (727462b)
- Merge branch 'worktree-agent-a2b325182b96548dd' into test/broad-coverage (c0d7c5a)
- Merge branch 'worktree-agent-a6a8b806dc28f22d5' into test/broad-coverage (ef51017)
- Merge branch 'worktree-agent-ae2d480d350f472c4' into test/broad-coverage (ed8d1f3)
- Merge branch 'worktree-agent-a596d168a13bf9617' into test/broad-coverage (d43d2c2)

## [0.4.2] - 2026-09-27

- **The block notice is three lines:** what kind of thing was found, the one next step (⌘V or
  Ctrl+V, or /ms), and where to report a wrong detection. What is stored and for how long is in
  `/maisecrets:list`.

### Features

- a three-line block notice - the kind found, the one next step, the report (efa93cd)

## [0.4.1] - 2026-09-27

### Fixes

- an expired entry no longer breaks status, list and a new paste of the same value (f8172bf)

## [0.4.0] - 2026-09-27

- **Changed for everyone:** the block notice is new (plain words, what was found, the prompt with the
  short forms, where the values stay and for how long), and the first session start only offers
  `/ms` (`/maisecrets:shortcut`) instead of installing it. An existing `/ms` keeps working.

- **The block notice speaks plainly** and shows what was found (masked), the prompt with the short
  forms, where the values stay and for how long.
- **`/maisecrets:list`** shows what is stored, masked; **`/maisecrets:forget <key>`** deletes one entry.
- **You see every redaction**: one line names the values replaced in a tool result.
- **The session start is shorter** and names no file paths; `/ms` is offered once instead of being
  installed, and Codex gets tips that work there.
- **The `secret-hygiene` skill** finds leaked secrets in a repository and its history (date, author,
  pushed or not, provider), guides the rotation, and writes redacted copies of files to share.

### Breaking

- the secret-hygiene skill, a plain block notice, /maisecrets:list and /maisecrets:forget (a77f8ad)

### Features

- audit the local Claude Code and Codex transcripts for secrets that already reached the provider (df96aba)
- a plain block notice that shows what was found and what would be sent; /maisecrets:list and /maisecrets:forget; the skill reports date, author, pushed state, provider and every skip (91e5b79)
- secret-hygiene finds leaked secrets by location, guides the rotation, writes redacted copies (fb5ef18)

### Fixes

- the skill tests run in CI and a skipped test is no proof; the release waits for the beliefs replay (2750b3b)
- review findings - a ++ line is content, labels in a sentence, expire keeps its lock, the scrub keeps bytes and mode; feat(skill): the ChatGPT listing and a flat zip (37c330b)
- the scan runs on every core, keyword rules only near their keywords, no size limit; fix(beliefs): each replay run gets a fresh bytecode cache (2b969e2)

### Other

- Merge branch 'main' into feat/secret-hygiene-skill (d22334e)
- Merge remote-tracking branch 'origin/main' into feat/secret-hygiene-skill (de7f2df)

## [0.3.33] - 2026-09-27

- **An MCP call that gets a real value now asks you first** (Claude Code), also in auto and bypass
  mode, with a warning when the value sits in a message body or another published text. Unattended
  runs (`claude -p`) refuse it. On Codex, which cannot ask, a placeholder in such a text field is refused.

### Fixes

- an MCP call gets a real value only after the user confirms; Codex refuses a value in published text (bdb5589)

## [0.3.32] - 2026-09-27

### Fixes

- no .claude-plugin/icon.svg, so the portal reads the icon URL from the manifest; a 30-character subtitle for OpenAI (16e9e0b)

## [0.3.31] - 2026-09-27

### Fixes

- verify_release expects the Codex manifest in the release commit; the test reads that list too (2bdb33f)

## [0.3.30] - 2026-09-27

### Fixes

- a reader retries while another hook process replaces the index or the store (Windows PermissionError) (bfb211c)
- the release job stages the Codex manifest it bumps; a test reads the job's git add line (c67483a)
- the manifest icon is the URL of the PNG on main, which the listing preview renders (bc7f087)

## [0.3.29] - 2026-09-27

### Features

- a Codex manifest with the interface fields and icon; hooks.log names the desktop entry point (da5db56)

## [0.3.28] - 2026-09-27

### Features

- the mcpgate mark as the plugin icon (7594fb5)

### Fixes

- a PNG as the manifest icon (cce176d)
- the icon in every place a listing looks for it (5cbb758)
- block and redaction notices one fact per line, and no slash commands on Codex (953da8b)

## [0.3.27] - 2026-09-27

### Features

- privacy page and the listing URLs in the manifest (bc376f0)

## [0.3.26] - 2026-09-27

### Fixes

- exact allowed-tools per command, a plugin icon, no environment token in the GitHub wait (6bbbaa3)

## [0.3.25] - 2026-09-27

- `/maisecrets:shortcut --remove` takes the personal `/ms` away and keeps it away.

### Fixes

- a revert releases as a patch; tests for the operations paths and the release tools (4273160)

## [0.3.24] - 2026-09-27

### Features

- the first session start installs a personal /ms once, unless one exists or shortcut is off (503cf08)

### Fixes

- the plugin's own command names are never a labelled secret (a6b1f6c)

## [0.3.23] - 2026-09-26

- The first session start installs a personal `/ms` for `/maisecrets:send` (unless one exists
  or `"shortcut": false`); `/maisecrets:shortcut [name]` does it by hand.
- `/maisecrets:put` explains the SSH case (no clipboard: use a label in a prompt).

### Features

- /maisecrets:shortcut installs a personal /ms; the answer to a sent prompt shows the text (53553e7)

### Fixes

- one path separator style in the wrapper under Git Bash (9c31784)
- the wrapper honours HOME under Git Bash on Windows (b39ab76)

## [0.3.22] - 2026-09-26

- **Codex users: re-trust the hooks once in `/hooks` after this update.** `hooks/hooks.json`
  changed (Write/Edit/MultiEdit/NotebookEdit joined the PreToolUse matcher, and every hook
  has a `commandWindows` entry). Until the hooks are trusted again, Codex runs no maisecrets
  hook and says nothing.
- The plaintext `jsonfile` store now needs `"allow_plaintext_store": true` in the config
  (or the policy); it is the test store.
- A wrong type or an unknown key in `~/.maisecrets/config.json` no longer changes anything
  silently: the strict defaults apply and the session start names the key. A broken machine
  policy file blocks every prompt and names the key.
- Keychain values are stored base64-marked (`b64:`), so umlauts round-trip; entries written
  by earlier versions are still read.
- Every hook run is recorded in `~/.maisecrets/hooks.log` (no value, no command).
- Write, Edit, MultiEdit and NotebookEdit resolve a placeholder in their content like an MCP
  argument (session rule, cap, audit line with the file name); `"resolve_in_files": false`
  turns that off.
- Requires Python 3.11+; without it every prompt is blocked and the message names what to
  install.

### Features

- Write and Edit resolve a placeholder like an MCP argument; Windows run dir without uid (9b1cf00)
- second review round applied - private FIFO dir, shell-context scanner, model-facing texts, policy file, retention (099032d)

### Fixes

- the block notice says a placeholder resolves only where maisecrets is active (e2a1db4)
- the primer allows a value in a file or a command when the user asks for it (1a60541)
- second-round findings - command-word refusals, no POSIX grants, private tmp run dir, config fallback, keychain line limit, hooks.log (71e2826)

## [0.3.21] - 2026-09-26

### Features

- Codex on Windows runs the hooks through a PowerShell launcher (c8d0606)

### Fixes

- the Codex launcher is a batch file, run as cmd.exe /C like Codex does (e7bd8d2)

## [0.3.20] - 2026-09-26

### Fixes

- the up-front read tests accept the resolver form Git Bash uses (061258b)
- fail closed on the plugin's own faults and deliver Bash values through a FIFO read up front in the main shell (9170416)

## [0.3.19] - 2026-09-26

### Features

- /maisecrets:send sends the kept rewritten prompt without a clipboard; a failed resolve terminates the command; a grant serves retries; a copied nonce is denied (caf0a98)

### Fixes

- retry the atomic replace while another process reads the index (WinError 5 under concurrency) (4f671dd)
- the lock is taken per index mutation, not for a process's life; the Codex harness preloads in a subprocess; tests keep the open lock file; the release gate steps aside when main moved on (c723767)
- hook processes running at once no longer break each other: per-process temp files, one lock per vault home, unique scrub temp names (6b0ab8c)

## [0.3.18] - 2026-09-26

### Fixes

- the blocked prompt and an MCP resolve are scrubbed from the transcript by a detached child that waits for the record; the harness now really checks transcripts (353643b)

## [0.3.17] - 2026-09-26

### Fixes

- drop the root plugin.json, with it Codex discovered none of the four hooks; the Codex harness installs the plugin through Codex's own discovery (723bb8f)

## [0.3.16] - 2026-09-26

### Fixes

- a labelled value counts from 8 characters, said in the tip and the README (97701a0)

## [0.3.15] - 2026-09-26

### Features

- bare token prefixes live in rules/prefixes.txt, one line each, extended by pull request; CONTRIBUTING.md (4a66d5c)

## [0.3.14] - 2026-09-26

### Fixes

- Cloudflare user API tokens (cfut_) are a secret shape when bare; gitleaks 8.30 needs the word cloudflare and an assignment sign (e17ff23)

## [0.3.13] - 2026-09-26

### Features

- one short tip per day at session start (label a password, /maisecrets:put, session rule, report, audit); off with tips=false (8d6a66c)

## [0.3.12] - 2026-09-26

### Features

- German credential labels (passwort, kennwort, geheimnis, schluessel, zugangsdaten); /maisecrets:put stores the clipboard value and hands back the placeholder (3b67aaa)

## [0.3.11] - 2026-09-26

### Fixes

- release token recreated after the namespace move dropped every project access token; GitLab stays under the personal namespace (cbe8995)

## [0.3.10] - 2026-09-26

### Features

- /maisecrets:report bug <text> and feature <text> open a prefilled issue without a detection event (bb07a67)

## [0.3.9] - 2026-09-26

### Fixes

- a span that contains a placeholder is never a hit (curl -u app:⟦SECRET_c1⟧ minted a second reference); README opens with what the user sees (bd1e9b3)

## [0.3.8] - 2026-09-26

### Fixes

- every file read names UTF-8; the audit-log test read the file with the platform encoding and failed on windows-latest (254cc36)

## [0.3.7] - 2026-09-26

### Features

- notify the claude.ai organisation marketplace from the tag pipeline with a signed push event (41da293)

## [0.3.6] - 2026-09-26

### Fixes

- webhook signing secrets (whsec_) are a secret shape; a bare one on its own line passed. References are numbered in text order (3a9ce0b)

## [0.3.5] - 2026-09-26

### Fixes

- drop userConfig, which Claude Code 2.1.223 rejects as an invalid manifest and then loads no hook at all; the harness fails when the plugin did not load (29e75d9)

## [0.3.4] - 2026-09-26

### Fixes

- a fixed-length secret shape is extended to the end of the token run; harnesses check the marker tail (56b3a92)

## [0.3.3] - 2026-09-26

### Features

- /maisecrets:report and maisecrets report open a prefilled GitHub issue from the last detection event, never with a value (991d1de)

## [0.3.2] - 2026-09-26

### Fixes

- the creating session always may resolve an entry, also for entries written before the sessions list existed (b649f66)

## [0.3.1] - 2026-09-26

### Fixes

- while the major is 0, feat and fix bump the last number and only a breaking change bumps the middle one (6fc978f)

## [0.3.0] - 2026-09-26

### Features

- session-bound references, one-time grants for Bash, MCP argument resolution, exact-match redaction, limiter and audit log (f337394)

## [0.2.0] - 2026-09-26

### Features

- release job derives the version from commit subjects, tags, and mirrors main and tags to GitHub over a deploy key (52eacb2)

## [0.1.0] - 2026-09-26

- Day-1 prototype: detector (patterns from an earlier internal scrubber), placeholder
  tokens `<TYPE_cN:display>`, vault with TTL and metadata index (jsonfile and
  macOS keychain backends), three Claude Code hooks, harness with a fake
  Anthropic upstream, 4 scenarios, golden hook payload shapes.
- Detector as data: gitleaks, Presidio and detect-secrets rulesets vendored;
  placeholder `⟦TYPE_cN:display⟧` aligned with the gateway; keychain, Credential
  Locker and encrypted-file backends with TTL; Codex adapter; harnesses for
  Claude Code and Codex against fake upstreams.

From 0.2.0 on, every section above is generated by `scripts/release.py` from the
commit subjects since the previous tag.
