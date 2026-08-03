# wks-diary-core Syntax -- Worked Examples

## people/max_mustermann.txt
```
[*Max Mustermann[max_mustermann.txt]*]
[aliases: Max, Maxi, Mustermann]

Met at university, studies computer science.
Lives in Munich. Big fan of #minecraft-server projects.
```

## people/lena.txt
```
[*Lena Vogel[lena.txt]*]
[aliases: Lena, Le]

Childhood friend, now studying medicine in Regensburg.
```

## diary/kapitel-01/2026-08-03.txt
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

## misc/ideen.txt
```
## sync-idea

Idea: server should reject a push if the base hash doesn't match,
so two devices can never silently overwrite each other.

## other-idea

Unrelated note, kept in the same file under its own heading.
```

## Failure Cases

- `*Alex*` with no matching alias -> unresolved mention warning.
- `[*Max Mustermann[max.txt]*]` inside a file actually named `max_mustermann.txt` -> self-mismatch error.
- Two people files both declaring `[aliases: Max]` -> duplicate alias error.
