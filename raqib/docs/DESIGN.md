# The console's design system

The console is not a dashboard template. It follows the
[frontend-design](https://github.com/anthropics/skills) guidance: commit to a
direction, then execute it precisely.

## The direction

**"Instrument panel at 3am."**

Industrial and utilitarian, with an editorial spine. It should feel like a
device built by someone who uses it at night, not like a SaaS dashboard. The
reference points are a spectrum analyser, a field notebook, and a newspaper
index page — not a card grid.

Deliberate rejections:

- no Inter, Roboto, Arial or system fonts;
- no purple gradients on white;
- no rounded, shadowed "cards";
- no centred hero, no emoji, no icon font.

## Typography

| Role | Face | Why |
|---|---|---|
| Display | **Bricolage Grotesque** (200–800) | a variable grotesque with unusual proportions and a slight mechanical edge; it carries the wordmark and the section titles without sounding like a brand font |
| Interface | **IBM Plex Sans** (400/500) | humanist, engineered, legible at 13 px; it never competes with the display face |
| Evidence | **IBM Plex Mono** (400/500) | paths, sizes, hashes and channel names are read as data, not as prose |

All three are inlined as base64 woff2 in the bundle, so the console needs no
network and no font CDN. The whole typographic system is about 99 KB of
woff2, roughly 132 KB once base64-encoded.

## Colour

```
--ink       #0a0c0b   the page
--panel     #121716   instrument surfaces
--line      #222b28   hairlines
--bone      #e8e4d8   primary text (warm, not pure white)
--amber     #ffa62b   the signal colour: active, matched, selected
--phosphor  #56c7c0   verified, secondary data
--clay      #e05a34   limits, gaps, things not proven
```

One dominant dark ground, one sharp accent (amber), two supporting accents
used sparingly and semantically: phosphor means *proven*, clay means *not
proven*. Nothing is tinted for decoration.

## Space and composition

The deck is a two-column grid, but the canvas **rides up over the rail's
first rule** — a small grid break that makes the page feel composed rather
than assembled. The rail is narrow (21.5 rem) and holds only inputs; the
canvas holds only results. The masthead spans the full width with the
wordmark, the build metadata and a single line of intent.

Panels carry **corner brackets** — two 11 px amber corners, top-left and
bottom-right — instead of borders on all four sides. The corners say
"instrument" without a shadow.

## Motion

One orchestrated page load, then micro-interactions:

- the masthead is swept by a single amber scanline that crosses once;
- panels and blocks rise into place with a staggered delay
  (`--d`, 60–90 ms apart) on `cubic-bezier(.16, 1, .3, 1)`;
- the status dot pulses while work is in flight;
- hover states are border-colour changes, not colour fades.

`prefers-reduced-motion: reduce` disables all of it, including the reveal.

## Texture and depth

Three layers, all cheap:

1. a 44 px blueprint grid at 4.5 % amber, fixed to the viewport;
2. two soft radial washes — cyan above, amber below — so the corners are not
   dead flat;
3. an SVG `feTurbulence` grain at 50 % opacity in `overlay` blend mode, plus
   a radial vignette.

Nothing here costs a network request or a layout shift.

## The evidence block

Facts are a two-column definition grid: a monospace label column and a
monospace value column, separated by a hairline. Locations are a numbered
list with a left rule that turns phosphor on hover. Limitations are dashed
clay boxes under the heading **"Not proven"** — deliberately the last thing
on the page, and the only thing in clay.

The stamp next to the evidence id reads `no gaps` when the run had no
limitations and `n gaps` when it did, and it is rotated two and a half
degrees, because a stamp should look stamped.

## Interaction

- `⏎` runs the analysis on the current path;
- `/` focuses the search pattern;
- `Esc` clears the search results;
- every location row is a copy target.

The console never fetches anything but its own origin: all API calls are
relative, so it works unchanged behind a proxy, in a container, or on a
machine with no route to the internet.
