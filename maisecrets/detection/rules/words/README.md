# Word lists of the detection rules

Each file holds the words of one rule, one entry per line. maisecrets reads them at the start
(`maisecrets/detection/wordlists.py`). To change what maisecrets masks, you change a file here; no
Python is needed.

## Find the file

1. Pick the folder of the kind of value: a name, an address, a password, …
2. Pick the effect:
   - **less**: maisecrets masks a value wrongly. A word here makes it mask less.
   - **more**: maisecrets misses a value. A word here makes it find more.
3. Read the head of the file. It says what the list holds and which code reads it.

A word in another language goes into the same file as its English word.

## Rules for a file

- One entry per line, lower case. A line that starts with `#` is a comment.
- A comment line inside the list opens a block. Put the word into the block whose comment fits,
  in its sorted place.
- Each entry once per file. `tests/test_word_lists.py` checks this and that this README names every file.
- One word can change the false alarms a lot. The maintainer measures the full benchmark splits
  before a merge.


## addresses/

Postal addresses: the cues and labels before a street, words that are no street.

| File | Effect | What it holds |
|---|---|---|
| `addresses/address-cues.txt` | more | the text must hold one of these words before the rule for an address after a label runs. |
| `addresses/not-a-street.txt` | less | the names of products, tools and fillers that a test or a seed writes after an address label (Gate A of #49) |
| `addresses/street-key-words.txt` | more | a key that holds the street line of a postal address (Cloakroom 1.4.0 rules.py:134-138): street, address_line1 … |
| `addresses/street-keys.txt` | more | keys whose value is the street line of an address, folded: lower case, without separators. |
| `addresses/street-labels.txt` | more | the text must hold one of these words before the rule for a street after a label runs. |

## birth-dates/

Birth dates: the cues before a date.

| File | Effect | What it holds |
|---|---|---|
| `birth-dates/birth-cues.txt` | more | words one of which a text must hold before a rule's regex runs (a cheap test on the lowered text) |

## emails/

Mail addresses: service mailboxes, owner columns, file names that look like an address.

| File | Effect | What it holds |
|---|---|---|
| `emails/file-extensions.txt` | less | the extension of a file that an asset name ends in: name%402x.png is an image at twice the size. |
| `emails/owner-column-ends.txt` | more | an owner word before one of these is the same column: Recipient Address, Login Name, sender_addr. |
| `emails/owner-columns.txt` | more | the owner word must be the last word of the header: login_user and user are addresses, end_user_id and. |
| `emails/service-mailboxes.txt` | less | the local part of a mail address of a service, not of a person: alerts@, backup@. |
| `emails/system-users.txt` | less | the local part of a mail address of a system account: git@, ec2-user@. |

## id-numbers/

ID numbers: the keys, labels and context words of a national number.

| File | Effect | What it holds |
|---|---|---|
| `id-numbers/at-social-security-context.txt` | more | a word near an Austrian social security number that names it; without one the number stays text. |
| `id-numbers/ch-ahv-context.txt` | more | a word near a Swiss AHV number without dots that names it. |
| `id-numbers/de-id-card-context.txt` | more | a word near a German ID card number that names it. |
| `id-numbers/de-passport-context.txt` | more | a word near a German passport number that names it. |
| `id-numbers/de-tax-id-context.txt` | more | country rules of our own (0.6.19): forms Presidio has no pattern for, and Switzerland and Austria, which it ha … |
| `id-numbers/id-key-words.txt` | more | the text must hold one of these words before the rule for an id number under a key runs. |
| `id-numbers/id-keys.txt` | more | a key whose value is an id number of a person (Privy, the Benchmark V3 sample, 2026-11-14) |
| `id-numbers/id-label-words.txt` | more | a word in a label before an id number of a person: passport, licence, member. |
| `id-numbers/vat-id-context.txt` | more | a word near a Swiss or Austrian VAT id that names it. |

## name-service/

Words that the name service (NER) takes for a person when they stand alone.

| File | Effect | What it holds |
|---|---|---|
| `name-service/greetings.txt` | less | greetings and salutations that are no person alone. |
| `name-service/hook-events.txt` | less | the hook events of Claude Code and Codex: a tool name after PostToolUse: is no person. |
| `name-service/never-a-name.txt` | less | words that are never a name in any language: no person alone, and never stored. |
| `name-service/path-words.txt` | less | the folder names of a file path: no person next to a / or a \\. |
| `name-service/product-name-tails.txt` | less | words after a product word in a product name: Claude Code, GitHub Actions. |
| `name-service/product-tails-that-are-names.txt` | more | words of product-name-tails that stay a name after a product word: Server. |
| `name-service/product-words.txt` | less | product and model words that the name service takes for a person when they stand alone. |
| `name-service/test-runner-words.txt` | less | words of a test runner's or a build's summary line that are no person alone. |
| `name-service/tool-names.txt` | less | the tool names of Claude Code and Codex: no person in a hook label or a tool context. |
| `name-service/ui-labels.txt` | less | button and UI label words that are no person alone. |

## names/

A person's name: a word that is no name, a role, a label, a field state.

| File | Effect | What it holds |
|---|---|---|
| `names/de-not-a-name-after-a-title.txt` | less | a word after the title that names no one: a template field, a pronoun, a greeting, the title again. |
| `names/de-role-word-endings.txt` | less | the end of a German role word after a title: Oberarzt and Geschäftsführerin are roles, not names. |
| `names/de-roles-after-a-title.txt` | less | a role after the title: the word itself, or a compound that ends in one of the stems (Oberarzt, Geschäftsführe … |
| `names/field-states-under-a-name-key.txt` | less | one word in a name field that is the state of the field in a form or a schema, not a name; the word list knows … |
| `names/field-states.txt` | less | the state of a form field after its label, not a name: the word list holds the stems only (require, mandate) |
| `names/given-names-that-are-words.txt` | more | given names that are also English words (SCOWL); a value that starts with one may still be a person. |
| `names/language-names.txt` | less | names of a language in its own script: a locale table is no person. |
| `names/message-start-after-a-name-label.txt` | less | a word that starts a validation message or a changelog line after a name label. |
| `names/name-label-translations.txt` | less | the value of an i18n file or a form schema, not a name: the label in another language (first_name: Vorname) an … |
| `names/name-label-values.txt` | less | a value after a name label that is no name: the label translated, a type, a placeholder. |
| `names/not-a-name-first-word.txt` | less | the first word of a value that is no name. |
| `names/not-a-name-part.txt` | less | a word in a first or last name column that is no name: the words of fixtures and seed data. |
| `names/not-a-name-word.txt` | less | a word in a value that makes it an organisation, a product or a place, not a person. |
| `names/not-a-surname-after-a-title.txt` | less | a word after Mr or Mrs that is a role, not a surname: Mr Chairman. |
| `names/person-name-keys.txt` | more | a person-name key in structured data (#43) |
| `names/person-roles-before-a-name-key.txt` | more | a role before a person-name key (customer_first_name, billingLastName): the name is still a person's. Not user … |
| `names/role-field-values.txt` | less | one word in a role field of an API that is a state or a team, not a person (assignee: Unassigned, assignee: De … |
| `names/roles-in-a-salutation.txt` | less | the roles a salutation names instead of a person, which the word list lacks (Dear Valued Policyholder): read o … |
| `names/team-and-group-words.txt` | less | a word in the value of a role key that makes it a team, a group or an account, not a person. |

## passwords/

Passwords, keys and tokens: label words, and words that make a value code, prose or a message.

| File | Effect | What it holds |
|---|---|---|
| `passwords/algorithm-names.txt` | less | the parts of an algorithm name: a value made of them is an algorithm, not a password (aes256-gcm). |
| `passwords/code-types-and-keywords.txt` | less | a short glued value that is a type or a keyword of code or config, or a camelCase identifier: |
| `passwords/credential-parts.txt` | more | parts of a credential word, also glued to another word (mysecret, apikey, passwordhash); maisecrets is a produ … |
| `passwords/cursor-token-words.txt` | less | a word before `token` that makes the field the cursor of a paged list or a sync, not a credential (measured on. |
| `passwords/error-message-words.txt` | less | the word after a label in an error message or a log line: "pwd: expected bytes, got str" (Python standard libr … |
| `passwords/export-login-columns.txt` | more | a column of a password-manager export that holds the login, next to the password column. |
| `passwords/export-secret-column-pairs.txt` | more | two words of a column name of a password-manager export that together name a secret: api key. |
| `passwords/export-secret-columns.txt` | more | a column of a password-manager export that holds a secret. |
| `passwords/identifier-key-words.txt` | less | the word before `key` in the name of a key that is an identifier: file_key (Figma), partition_key, idempotency … |
| `passwords/identifier-words.txt` | less | a camelCase value with one of these words is an identifier of code, not a passphrase. |
| `passwords/known-words.txt` | less | words that the English word list lacks: a value made of words is no random secret. |
| `passwords/not-a-password-before-pass.txt` | less | a word before `pass` that makes it no password label: compass, by pass, first pass. |
| `passwords/not-a-password-cell.txt` | less | what a cell of a schema, a form or a masked export holds instead of a password. |
| `passwords/not-a-password-label.txt` | less | a word in a password label that makes it a UI or code label, not a password: password_hint. |
| `passwords/not-a-secret-key-word.txt` | less | a word before `key` or `token` that makes the field no secret: cache key, captcha token. |
| `passwords/one-time-password-cues.txt` | more | a TOTP or HOTP seed: base32 of 10 to 40 bytes after a one-time-password label (otpauth://… carries it as secre … |
| `passwords/password-key-ends.txt` | more | a key whose value is a password (key_store_password, current-password, keypassword, db_pwd); a key that names … |
| `passwords/password-label-words.txt` | more | the last word of a password label, and the words before it that make the label name something else. |
| `passwords/password-translations.txt` | more | words that the English list lacks: short words, code identifiers, algorithm names, German words of developer p … |
| `passwords/prose-about-a-password.txt` | less | prose about a password, not one: a hyphen compound whose last part says what was done to it (SHA256-hashed,. |
| `passwords/revision-label-ends.txt` | less | the last word of a label of a revision: a hex value after commit or sha is no secret. |
| `passwords/secret-key-words.txt` | more | a word in a field name that names a secret: password, secret, token. |
| `passwords/secret-name-parts.txt` | more | a part of a variable name that names a secret: a random value after it is masked. |
| `passwords/short-english-words.txt` | less | English words of two and three letters (the word list starts at four): the verb of a CI step name, `Run Pytest … |
| `passwords/time-and-state-label-ends.txt` | less | the last word of a label that names a time or a state of a secret: lastPasswordChangeDateTime, password_set. |
| `passwords/time-label-verbs.txt` | less | `at` and `on` end such a label only after a verb: token_expires_at, secretCreatedAt; not secret_at or api_key_ … |

## phones/

Phone numbers: the cues and keys before a number.

| File | Effect | What it holds |
|---|---|---|
| `phones/phone-cues.txt` | more | a word before a phone number that makes it a person's number: call, cell, my number is. |
| `phones/phone-key-qualifiers.txt` | more | a word next to phone in a key: phone_home, mobileBusiness. |
| `phones/phone-keys.txt` | more | a phone word with qualifiers only names a phone: phone_home, telefon_privat, mobileBusiness, phone_cell. A nam … |

## placeholders/

Placeholder names and values of documentation and tests.

| File | Effect | What it holds |
|---|---|---|
| `placeholders/name-words.txt` | less | the surnames and given names of documentation, which the name rule finds as a pair. |
| `placeholders/password-words.txt` | less | the word for password itself before a number (Passwort1, Salasana1, Haslo2024) is an example in every language … |
| `placeholders/person-names.txt` | less | placeholder person names of documentation and tests. |
| `placeholders/surnames.txt` | less | the last names of the placeholder names of documentation (personal.PLACEHOLDER_NAMES) |
| `placeholders/value-parts.txt` | less | a part of a value that makes it a placeholder: your_, dummy, example, <redacted. |
| `placeholders/values.txt` | less | a value that is obviously a placeholder is never a secret, whichever rule matched it. |

## tables/

Tables, CSV, SQL and JSON: the columns and parents that hold personal data, and those that do not.

| File | Effect | What it holds |
|---|---|---|
| `tables/birth-date-columns.txt` | more | a column of a birth date: it makes the table a table of persons. |
| `tables/first-name-columns.txt` | more | a column of a first name. |
| `tables/id-columns.txt` | more | a column of an id number that only a person has. |
| `tables/name-part-columns.txt` | more | a field that names one part of a name holds one word (/ First Name / X /): a record with a person in it says s … |
| `tables/person-parents-of-a-name.txt` | more | a parent whose name field names a person: its string is read after `<parent>_name` (author_name), a person lab … |
| `tables/person-parents-of-an-id.txt` | more | a parent element whose id number is a person's: applicant, employee, holder. |
| `tables/personal-columns-weak.txt` | more | a column of a person in a role; weak, so it counts only next to a strong column. |
| `tables/personal-columns.txt` | more | a header with a column that holds personal data on every row. A name or a user column alone is no proof (a pro … |
| `tables/software-columns.txt` | less | a column of a software table: next to it a name column names a product, not a person. |
| `tables/sql-not-a-column.txt` | less | an SQL word in CREATE TABLE that is no column: primary, key, constraint. |
| `tables/thing-parents.txt` | less | the parent of a name element that is a thing, not a person: a pom.xml project, a product, a package, and the. |
| `tables/value-wrappers.txt` | more | a last part that only holds the value of the object above it: {"phone": [{"value": ...}]}, {"phone": {"number" … |

## usernames/

User names: service accounts, tool and bot parts, user-name keys.

| File | Effect | What it holds |
|---|---|---|
| `usernames/code-attribute-ends.txt` | less | the last part of an attribute in code: `username=authn.principal`, `username: current.user`. |
| `usernames/not-a-person-ends.txt` | less | the last word of a field, a role or a variable, not of a person's name: ci_actor, database_owner, enum_value. |
| `usernames/not-a-value.txt` | less | a value after a user-name label that is no user name: empty, false, my_username. |
| `usernames/service-accounts.txt` | less | user names of services and system accounts, never a person. |
| `usernames/tool-and-bot-parts.txt` | less | a part of a user name that names a daemon, a tool, a product or a bot, not a person. |
| `usernames/user-name-key-words.txt` | more | a key that holds a user name (#51): userID, login_name. |
| `usernames/user-name-keys.txt` | more | keys whose value is a user name, folded: lower case, without separators. |
