# wks-diary-core Syntax -- Worked Examples

## people/max_mustermann.md
```
[*Max Mustermann[max_mustermann.md]*]
[aliases: Max, Maxi, Mustermann]

Met at university, studies computer science.
Lives in Munich. Big fan of #minecraft-server projects.
```

## people/lena.md
```
[*Lena Vogel[lena.md]*]
[aliases: Lena, Le]

Childhood friend, now studying medicine in Regensburg.
```

## diary/kapitel-01/2026-08-03.md
```
[meta]
date: 2026-08-03
chapter: kapitel-01
mood: good
[/meta]

Spent the afternoon debugging the push endpoint with *Max*.
He suggested a hash-based fast-forward check, see [[misc/ideen#sync-idea]].

Later called *Le* about the weekend trip. \*Not a mention\*.

#wks-diary-core #debugging
```

## misc/ideen.md
```
## sync-idea

Idea: server should reject a push if the base hash doesn't match,
so two devices can never silently overwrite each other.

## other-idea

Unrelated note, kept in the same file under its own heading.
```

## Line-level merge example

Two devices both edit `diary/kapitel-01/2026-08-03.md` starting from the same base version:

- Device A appends a new paragraph about the evening.
- Device B fixes a typo in the morning paragraph.

Since these touch different, non-overlapping lines, the backend merges both changes automatically -- no conflict markers, no manual resolution needed, even though the file changed on both sides. Only truly overlapping edits (both sides rewriting the exact same paragraph differently) produce `<<<<<<<` markers, and only around that one paragraph, not the whole file.

## Failure Cases

- `*Alex*` with no matching alias -> unresolved mention warning.
- `[*Max Mustermann[max.md]*]` inside a file actually named `max_mustermann.md` -> self-mismatch error.
- Two people files both declaring `[aliases: Max]` -> duplicate alias error.
