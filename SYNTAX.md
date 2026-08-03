# wks-diary-core Markup Syntax Specification

## 1. Core Design Principles

- Every file is plain text and must remain human-readable even without a parser.
- Links and person-tags are resolved lazily, at read time, by scanning the vault.
- Ambiguity must always fail safely: an unresolved reference is flagged, never silently guessed.
- All syntax elements use ASCII characters only (`[`, `]`, `*`, `#`, `\`).

## 2. Person Definition Block

First non-empty line of every `people/*.txt` file:

```
[*Max Mustermann[max_mustermann.txt]*]
```

Syntax: `[*<DisplayName>[<filename>]*]`. `<filename>` must exactly match the file's own name.

### 2.1 Aliases

```
[*Max Mustermann[max_mustermann.txt]*]
[aliases: Max, Maxi, Mustermann]
```

## 3. Person Mentions (`*name*`)

`*token*` anywhere resolves via the global alias table built from all `people/*.txt` files.

- Exactly one match -> linked.
- No match -> unresolved mention warning, stays as plain text.
- Multiple matches -> ambiguous mention error.

Escape a literal asterisk: `\*not a mention\*`.

## 4. Cross-File Links (`[[...]]`)

```
[[diary/kapitel-01/2026-08-03]]
[[misc/ideen|the idea]]
[[diary/kapitel-01/2026-08-03#morning]]
```

Path relative to vault root, extension optional, pipe for display label, `#heading` for section anchor.

## 5. Topic Tags (`#tag`)

```
#triathlon #tired #minecraft-server
```

Lowercase, hyphenate multi-word tags. Purely an index feature.

## 6. Optional Metadata Header (Diary Entries)

```
[meta]
date: 2026-08-04
chapter: kapitel-02
mood: focused
[/meta]
```

Optional; falls back to filename/folder if omitted.

## 7. Comments

Lines starting with `//` are ignored by the parser.

## 8. Validation Rules

| Issue | Condition | Result |
|---|---|---|
| Unresolved mention | `*token*` matches no alias | Warning |
| Ambiguous mention | `*token*` matches 2+ people | Error |
| Broken link | `[[path]]` target missing | Warning |
| Self-mismatch | declared filename != actual filename | Error |
| Duplicate alias | same alias in 2+ people files | Error |

## 9. Reserved Characters Summary

| Syntax | Meaning |
|---|---|
| `[*Name[file.txt]*]` | Person definition |
| `[aliases: a, b, c]` | Alias list |
| `*token*` | Person mention |
| `\*text\*` | Escaped literal asterisks |
| `[[path]]` | Link |
| `[[path\|label]]` | Link with display text |
| `[[path#heading]]` | Link to a section |
| `#tag` | Topic tag |
| `[meta] ... [/meta]` | Metadata block (diary only) |
| `//` at line start | Comment |

## 10. Backlink Index

Rebuilt on every unlock from vault content; never part of the encrypted payload itself.
