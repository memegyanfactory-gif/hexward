// Writes the README brand images (SVG) from the same pixel grids the app and website use.
// Run: node scripts/brand-assets.js   (outputs to assets/brand/)
const fs = require("fs");
const path = require("path");
const out = path.join(__dirname, "..", "assets", "brand");
fs.mkdirSync(out, { recursive: true });

const MARK = [
  ".##############.", "################", "################", "######....######", "#####......#####", "####...oo...####",
  "####...oo...####", "#####......#####", "######....######", ".##############.", ".##############.", "..############..",
  "...##########...", "....########....", ".....######.....", "......####......",
];
// Hexward wordmark letters (5 x 7), from crates/app/src/art.rs
const HX = {
  h: ["#....", "#....", "####.", "#...#", "#...#", "#...#", "#...#"],
  e: [".....", ".....", ".###.", "#...#", "#####", "#....", ".####"],
  x: [".....", ".....", "#...#", ".#.#.", "..#..", ".#.#.", "#...#"],
  w: [".....", ".....", "#...#", "#...#", "#.#.#", "#.#.#", ".#.#."],
  a: [".....", ".....", ".###.", "....#", ".####", "#...#", ".####"],
  r: [".....", ".....", "#.##.", "##..#", "#....", "#....", "#...."],
  d: ["....#", "....#", ".####", "#...#", "#...#", "#...#", ".####"],
};
// OnuriLabs letters (6 x 7, 2-pixel stems), from web/shared/onuri.js
const OL = {
  O: [".####.", "##..##", "##..##", "##..##", "##..##", "##..##", ".####."],
  N: ["##..##", "###.##", "######", "##.###", "##..##", "##..##", "##..##"],
  U: ["##..##", "##..##", "##..##", "##..##", "##..##", "##..##", ".####."],
  R: ["#####.", "##..##", "##..##", "#####.", "##.##.", "##..##", "##..##"],
  I: ["######", "..##..", "..##..", "..##..", "..##..", "..##..", "######"],
  L: ["##....", "##....", "##....", "##....", "##....", "##....", "######"],
  A: [".####.", "##..##", "##..##", "######", "##..##", "##..##", "##..##"],
  B: ["#####.", "##..##", "##..##", "#####.", "##..##", "##..##", "#####."],
  S: [".#####", "##....", "##....", ".####.", "....##", "....##", "#####."],
};
const word = (text, glyphs) => {
  const rows = Array(7).fill("");
  [...text].forEach((c, i) => glyphs[c].forEach((r, y) => (rows[y] += (i ? "." : "") + r)));
  return rows;
};
// Merges horizontal runs into rects, one <path> per color class.
const paths = (rows, ox, oy, colorOf) => {
  const by = {};
  rows.forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      const c = colorOf(row[x], x, row.length);
      if (!c) { x++; continue; }
      let w = 1;
      while (x + w < row.length && colorOf(row[x + w], x + w, row.length) === c) w++;
      (by[c] = by[c] || []).push(`M${ox + x} ${oy + y}h${w}v1h-${w}z`);
      x += w;
    }
  });
  return Object.entries(by).map(([cls, d]) => `<path class="${cls}" d="${d.join("")}"/>`).join("");
};
const style = (light, dark) =>
  `<style>${Object.entries(light).map(([k, v]) => `.${k}{fill:${v}}`).join("")}@media (prefers-color-scheme:dark){${Object.entries(dark).map(([k, v]) => `.${k}{fill:${v}}`).join("")}}</style>`;
const markColor = (ch, x, w) => (ch === "#" ? (x < w / 2 ? "hi" : "lo") : ch === "o" ? "core" : null);
const inkColor = (ch) => (ch === "#" ? "ink" : null);
const svg = (w, h, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" shape-rendering="crispEdges">${body}</svg>\n`;
const marks = { hi: "#2FB463", lo: "#1A7F45", core: "#F0743A", ink: "#0B0F14" };
const marksDark = { hi: "#4BE07A", lo: "#23A05A", core: "#F0743A", ink: "#E6EDF3" };

// Hexward mark alone
fs.writeFileSync(path.join(out, "hexward-mark.svg"), svg(16, 16, style(marks, marksDark) + paths(MARK, 0, 0, markColor)));
// Hexward lockup: mark (16 tall) + wordmark (7 tall) centered, 4-unit gap
const hw = word("hexward", HX);
const lockW = 16 + 4 + hw[0].length;
fs.writeFileSync(
  path.join(out, "hexward-lockup.svg"),
  svg(lockW, 16, style(marks, marksDark) + paths(MARK, 0, 0, markColor) + paths(hw, 20, 4.5, inkColor)),
);
// OnuriLabs mark (the "O" favicon) and wordmark
const lab = { ink: "#0B0B0C" }, labDark = { ink: "#FFFFFF" };
const O = OL.O.map((r) => r);
fs.writeFileSync(path.join(out, "onurilabs-mark.svg"), svg(6, 7, style(lab, labDark) + paths(O, 0, 0, inkColor)));
const ow = word("ONURILABS", OL);
fs.writeFileSync(path.join(out, "onurilabs-wordmark.svg"), svg(ow[0].length, 7, style(lab, labDark) + paths(ow, 0, 0, inkColor)));
console.log("wrote", fs.readdirSync(out).join(", "));
