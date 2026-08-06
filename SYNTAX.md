# wks-diary-core Markup Syntax Specification

All vault files use the `.md` extension (plain Markdown-compatible text with a few extra reserved constructs). Earlier drafts used `.txt` -- that was changed because everything here is meant to render fine as normal Markdown too, and `.md` makes editors/viewers treat it correctly by default.

## 1. Core Design Principles

- Every file is plain text and must remain human-readable even without a parser.
- Links and person-tags are resolved lazily, at read time, by scanning the vault.
- Ambiguity must always fail safely: an unresolved reference is flagged, never silently guessed.
- All syntax elements use ASCII characters only (`[`, `]`, `*`, `#`, `\`).

## 2. Person Definition Block

First non-empty line of every `people/*.md` file:

```
[*Max Mustermann[max_mustermann.md]*]
```

Syntax: `[*<DisplayName>[<filename>]*]`. `<filename>` must exactly match the file's own name.

### 2.1 Aliases

```
[*Max Mustermann[max_mustermann.md]*]
[aliases: Max, Maxi, Mustermann]
```

## 3. Person Mentions (`*name*`)

`*token*` anywhere resolves via the global alias table built from all `people/*.md` files.

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

Path relative to vault root, extension optional (resolves to `.md`), pipe for display label, `#heading` for section anchor.

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

The backend now also runs this validation automatically on every push (after merge/fast-forward) and returns the report in the response, so you see problems immediately instead of only on your next local `validate` run.

## 9. Reserved Characters Summary

| Syntax | Meaning |
|---|---|
| `[*Name[file.md]*]` | Person definition |
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

## 11. Merge conflict markers

When two edits to the same `.md` file genuinely conflict, the merge inserts standard-looking conflict markers around just the conflicting lines (not the whole file):

```
<<<<<<< remote
... server's version of this paragraph ...
=======
... your version of this paragraph ...
>>>>>>> incoming
```

Resolve by editing the file and removing the markers you don't want, exactly like resolving a Git merge conflict.
