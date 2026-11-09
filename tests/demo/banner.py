#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Баннер README и превью для соцсетей из скриншота docs/screenshots/_hero.webp.
Запуск после screens.py: python3 tests/demo/banner.py
→ docs/banner.webp (1600×560) и docs/social-preview.jpg (1280×640)
"""
import asyncio
import base64
import os

from playwright.async_api import async_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = os.path.join(ROOT, "docs")
CHROME = os.environ.get("CHROME")

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@500;600&family=IBM+Plex+Sans:wght@400;600;700&display=swap">
<style>
*{box-sizing:border-box;margin:0}
body{width:%(w)dpx;height:%(h)dpx;overflow:hidden;font-family:'IBM Plex Sans',system-ui,sans-serif;
  background:#0D1013;color:#E6E9ED;position:relative}
.grid{position:absolute;inset:0;background-image:linear-gradient(#ffffff08 1px,transparent 1px),linear-gradient(90deg,#ffffff08 1px,transparent 1px);background-size:40px 40px}
.glow{position:absolute;width:900px;height:900px;border-radius:50%%;right:-260px;top:-300px;background:radial-gradient(#3FAA6430,transparent 62%%)}
.left{position:absolute;left:%(pad)dpx;top:0;bottom:0;width:%(lw)dpx;display:flex;flex-direction:column;justify-content:center;gap:%(gap)dpx}
.brand{display:flex;align-items:center;gap:14px}
.logo{width:52px;height:52px;border-radius:14px;background:#E6E9ED;color:#0D1013;display:grid;place-items:center}
.name{font-size:%(nf)dpx;font-weight:700;letter-spacing:-.02em}
h1{font-size:%(hf)dpx;line-height:1.12;font-weight:700;letter-spacing:-.02em}
h1 span{color:#62CC88}
p{font-size:%(pf)dpx;line-height:1.45;color:#9BA5B0;max-width:%(lw)dpx}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{font:600 %(cf)dpx 'IBM Plex Mono',monospace;padding:6px 11px;border-radius:999px;border:1px solid #3A434D;color:#C6CDD5}
.chip.r{border-color:#B42318;color:#FF8F85}.chip.w{border-color:#A34C00;color:#FFB95E}.chip.g{border-color:#22492F;color:#62CC88}
.shot{position:absolute;left:%(sx)dpx;top:%(sy)dpx;width:%(sw)dpx;border-radius:14px;overflow:hidden;
  box-shadow:0 30px 80px #000a,0 0 0 1px #ffffff1a;transform:perspective(1800px) rotateY(-9deg) rotateX(3deg);transform-origin:left center}
.bar{height:30px;background:#1C2127;display:flex;align-items:center;gap:7px;padding:0 12px}
.bar i{width:10px;height:10px;border-radius:50%%;background:#3A434D}
.shot img{display:block;width:100%%}
</style></head><body><div class="grid"></div><div class="glow"></div>
<div class="left">
  <div class="brand"><div class="logo"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-6 5 12 2.5-6H21"/></svg></div><div class="name">ТСПУ-монитор</div></div>
  <h1>Видно, <span>что</span> заблокировано<br>и <span>как</span> — сразу</h1>
  <p>Следит за рабочими сервисами из офисной сети и поднимает тревогу в браузере, когда их начинает резать ТСПУ.</p>
  <div class="chips"><span class="chip r">SNI</span><span class="chip r">IP</span><span class="chip r">TCP 16-20</span><span class="chip r">DNS</span><span class="chip w">белые списки</span><span class="chip g">Docker</span></div>
</div>
<div class="shot"><div class="bar"><i></i><i></i><i></i></div><img src="data:image/webp;base64,%(img)s"></div>
</body></html>"""


async def render(p, b, w, h, dims, out, fmt):
    img = base64.b64encode(open(os.path.join(DOCS, "screenshots", "_hero.webp"), "rb").read()).decode()
    html = PAGE % dict(w=w, h=h, img=img, **dims)
    page = await b.new_page(viewport={"width": w, "height": h}, device_scale_factor=2)
    await page.set_content(html)
    await page.wait_for_timeout(1500)
    png = out + ".png"
    await page.screenshot(path=png)
    from PIL import Image
    im = Image.open(png).convert("RGB")
    if fmt == "webp":
        im.save(out, "WEBP", quality=86, method=6)
    else:
        im.resize((w, h), Image.LANCZOS).save(out, "JPEG", quality=90, optimize=True)
    os.remove(png)


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(**({"executable_path": CHROME} if CHROME else {}))
        await render(p, b, 1600, 560, dict(pad=72, lw=560, gap=22, nf=24, hf=50, pf=19, cf=13, sx=720, sy=64, sw=1000),
                     os.path.join(DOCS, "banner.webp"), "webp")
        await render(p, b, 1280, 640, dict(pad=60, lw=500, gap=22, nf=22, hf=44, pf=18, cf=12, sx=600, sy=110, sw=860),
                     os.path.join(DOCS, "social-preview.jpg"), "jpg")
        await b.close()
    os.remove(os.path.join(DOCS, "screenshots", "_hero.webp"))


if __name__ == "__main__":
    asyncio.run(main())
