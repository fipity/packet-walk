# Contributing to packet-walk

Thanks for helping! Bug reports, corrections, new lessons and translations are all welcome.

## Ground rules

- **Accuracy first.** Each packet should be one that could really appear on a wire. If
  you simplify something, say so in the lesson text or the README.
- **Plain language.** Lesson text is for curious beginners. Explain jargon the first time it appears.
- **Original content only.** Write your own explanations. Don't paste text from other
  sites or books. Quoting RFCs is fine.
- Run `npm test` and `npm run build` before opening a pull request.

## Adding a protocol

1. Write an encoder in `src/protocols/`. Use `Header` to append fields. Every field takes a
   name, a decoded value and an optional explanation (`info`).
2. Wrap the payload with `layer(name, kind, header, payload)`. If you need a new `kind`
   (it sets the colour), add it to `LayerKind` in `src/bytes.ts` and give it a colour
   (`--k-<kind>`) in `src/style.css`, in both the light and dark themes.
3. Fill in checksums afterwards with `patch16`.
4. Add a test if the protocol has any self-checking structure, such as lengths or checksums.

## Adding a lesson

Lessons live in `src/lessons/index.ts`. A lesson is a list of steps. Each step has a
`from` node, a `to` node, a title, an explanation and a packet. Use the helpers in
`src/lessons/network.ts` (`fromLaptop`, `toLaptop`, `TcpConn` and so on) so that
addresses, IP IDs and TCP sequence numbers stay consistent.

## Translating

- **UI strings:** copy the `en` dictionary in `src/i18n.ts`, translate the values,
  and register it in `LOCALES` (set `dir: 'rtl'` for right-to-left languages). The
  language picker appears automatically once there is more than one locale.
- **Lesson text:** any `title`, `text`, `intro` or `capture` string can become an object
  keyed by locale, for example `{ en: 'Hello', es: 'Hola' }`. Missing translations fall
  back to English.
