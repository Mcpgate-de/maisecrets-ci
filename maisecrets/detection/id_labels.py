"""The labels that make a number an id: a health, tax or national number, a passport or a driving licence
(id-number-after-label of personal.py). Kept out of personal.py, which is at the size limit of a release file."""
from __future__ import annotations

from .lazy_regex import LazyRx as _LazyRx

# --------------------------------------------------------------------------------- ID number after a label --
# the labels of health, tax and national numbers: the number of a health plan's beneficiary, a medical record, a
# national ID card, a tax ID and a social security number (Nemotron-PII writes them in its forms and notes, 2026-10-16)
# "beneficiary" and "social security" alone name a payee and a benefit (Beneficiary: VENDOR 00042)
_HEALTH_ID_LABELS = (r"|health[ _-]?plan[ _-]?beneficiary(?:[ _-]?(?:number|no\.?|id|#))?"
                     r"|beneficiary[ _-]?(?:number|no\.?|id|#)"
                     r"|medical[ _-]?record(?:[ _-]?(?:number|no\.?|#))?"
                     r"|national[ _-]?id(?:entification|entity)?(?:[ _-]?(?:number|no\.?|card))?"
                     r"|tax(?:payer)?[ _-]?id(?:entification)?(?:[ _-]?(?:number|no\.?))?|tin"
                     r"|social[ _-]?security[ _-]?(?:number|no\.?|#)")
# passport and driving licence in the label languages of the EU (Gretel writes them in its forms, 2026-10-16), and the
# English "driving licence": de, fr, es, it, nl, pt, sv, pl. "pass" alone is a password, "patente" alone a patent
_TRAVEL_ID_LABELS = (r"|driving[ _-]?licen[cs]e(?:[ _-]?(?:no|number))?"
                     r"|reisepass(?:[ _-]?(?:nummer|nr\.?))?|pass(?:nummer|[ _-]nr\.?)"
                     r"|f(?:ü|ue)hrerschein(?:[ _-]?(?:nummer|nr\.?))?"
                     r"|(?:num[ée]ro (?:de |du )?)?(?:passeport|permis de conduire)"
                     r"|(?:n[úu]mero (?:de |del |do )?)?(?:pasaporte|passaporte"
                     r"|(?:carn[ée]t|permiso|licencia) de conducir"
                     r"|carta de condu[çc][ãa]o|carteira de (?:motorista|habilita[çc][ãa]o))"
                     r"|(?:numero (?:di |del |della )?)?passaporto|numero (?:di |della )?patente|patente di guida"
                     r"|paspoort(?:nummer)?|rijbewijs(?:nummer)?|k[öo]rkort(?:snummer)?"
                     r"|(?:numer )?paszportu?|(?:numer )?praw[oa] jazdy")
_ID_RE = _LazyRx(r"(?i)(?<![a-z])(?:mrn|member[ -]?id|passport(?:[ _-]?(?:no|number))?|driver'?s? licen[cs]e"
                 r"(?:[ _-]?(?:no|number))?|dl[ _-]?(?:no|number|#)|(?-i:DL)(?=\s{0,3}[:#])|sin|tfn|nir|tax[ _-]?id"
                 r"|insurance (?:member )?id"
                 r"|account[ _-]?(?:number|no\.?)|(?:certificate[ _-]?)?licen[cs]e[ _-]?(?:number|no\.?)"
                 r"|patient[ -]?id|id on file" + _HEALTH_ID_LABELS
                 + _TRAVEL_ID_LABELS + r")(?![a-z])[\"']?"
                 r"(?:\s{0,3}(?:on file as|on file|is|was|of|number|no\.?|#|n\.?[º°o]\.?|nr\.?|num[ée]ro|n[úu]mero"
                 r"|numero|nummer|numer))?"
                 # a comma too: `your health plan beneficiary number, <id>, to medical professionals` (Nemotron-PII);
                 # bold, a table cell, a parenthesis after a space but not after sin, tin, nir, tfn (a call):
                 # `**medical record number** (<id>)`, `| Policy Number | <id>`
                 r"\s{0,3}\*{0,2}\s{0,3}(?:[:=#,|]|(?<![sStT][iI][nN]\s)(?<![nN][iI][rR]\s)(?<![tT][fF][nN]\s)(?<=\s)\()?\s{0,3}\*{0,2}\s{0,3}[\"']?"
                 r"((?-i:[A-Z0-9](?:[A-Z0-9]|[ -](?=[A-Z0-9])){4,24}))(?![A-Za-z0-9])")
# a date or the date and hour of a timestamp is no id: `2026-11-08T21` of a CI log line after `sin`, `tax id`
_ID_DATE_RE = _LazyRx(r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[T ](?:[01]\d|2[0-3])(?::[0-5]\d)?")
# only a timestamp with its hour: a plain date after an id label can be the id (a licence number written as a
# date, Nemotron; the 0.9.3 release gate)

_ID_WORDS = ("mrn", "member", "passport", "licen", "dl", "sin", "tfn", "nir", "tax", "insurance", "account",
             "patient", "id on file", "beneficiary", "medical", "national", "tin", "social",
             "reisepass", "passnummer", "pass-nr", "pass nr", "hrerschein", "passeport", "permis", "pasaporte",
             "passaporte", "conducir", "condu", "carteira", "passaporto", "patente", "paspoort", "rijbewijs",
             "körkort", "korkort", "paszport", "prawo jazdy", "prawa jazdy", "driving")
