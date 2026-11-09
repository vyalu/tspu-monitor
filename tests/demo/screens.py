#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скриншоты для README. Сначала запустите демо-стенд: python3 tests/demo/demo_server.py
Затем: python3 tests/demo/screens.py   → docs/screenshots/*.webp
Нужны: pip install playwright pillow  и  playwright install chromium
"""
import asyncio
import json
import os
import tempfile
import urllib.request

from playwright.async_api import async_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "docs", "screenshots")
URL = os.environ.get("DEMO_URL", "http://127.0.0.1:8099/")
SCEN = os.path.join(os.environ.get("DEMO_DIR", os.path.join(tempfile.gettempdir(), "tspu-demo")), "scenario")
CHROME = os.environ.get("CHROME")   # путь к Chrome, если нужен свой


def post(path, body=None):
    req = urllib.request.Request(URL + path, data=json.dumps(body or {}).encode(),
                                 headers={"Content-Type": "application/json", "X-TSPU": "1"})
    urllib.request.urlopen(req).read()


def scenario(name):
    open(SCEN, "w").write(name)


async def shot(page, name, full=False, clip=None):
    png = os.path.join(OUT, name + ".png")
    await page.screenshot(path=png, full_page=full, clip=clip)
    from PIL import Image
    Image.open(png).save(os.path.join(OUT, name + ".webp"), "WEBP", quality=88, method=6)
    os.remove(png)


async def checks(page, n=2):
    for _ in range(n):
        post("api/check")
        await page.wait_for_timeout(1300)
    await page.wait_for_timeout(3500)


async def main():
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch(**({"executable_path": CHROME} if CHROME else {}))
        ctx = await b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2, locale="ru-RU")
        page = await ctx.new_page()
        await page.add_init_script("try{localStorage.setItem('tspu.nbHidden','true')}catch(e){}")

        # 1. норма, вошли как администратор
        scenario("ok")
        await page.goto(URL)
        await page.wait_for_timeout(1500)
        await page.click("#loginBtn")
        await page.fill("#lUser", "admin")
        await page.fill("#lPass", "admin")
        await page.click("#lSubmit")
        await checks(page, 1)
        await shot(page, "dashboard")

        # 2. сбой: тревога поверх страницы
        scenario("fail")
        await checks(page, 2)
        await page.wait_for_selector("#alertScrim:not([hidden])", timeout=15000)
        await shot(page, "alert")
        await page.click("#alOk")
        await page.wait_for_timeout(400)
        await shot(page, "fail")

        # 3. история и диагностика CRM
        await page.click("button[data-act=hist] >> nth=0")
        await page.wait_for_timeout(600)
        await page.click("#rWeek")
        await page.wait_for_timeout(1500)
        await shot(page, "history")
        await page.click("#hClose")

        # 4. режим белых списков (сначала CRM восстанавливается — ждём, пока уйдёт его уведомление)
        scenario("ok")
        await checks(page, 1)
        await page.wait_for_timeout(8500)
        scenario("whitelist")
        await checks(page, 2)
        if await page.is_visible("#alertScrim"):
            await page.click("#alOk")
        await page.wait_for_timeout(400)
        await shot(page, "whitelist")

        # 5. настройки
        await page.click("#settingsBtn")
        await page.wait_for_timeout(400)
        await shot(page, "settings")
        await page.click("#sCancel")
        await page.wait_for_timeout(8500)

        # 6. тёмная тема на телефоне, норма
        scenario("ok")
        await checks(page, 2)
        await page.click("#themeBtn")
        mob = await b.new_context(**p.devices["iPhone 13"], locale="ru-RU", color_scheme="dark")
        mpage = await mob.new_page()
        await mpage.add_init_script("try{localStorage.setItem('tspu.nbHidden','true');localStorage.setItem('tspu.theme','dark')}catch(e){}")
        await mpage.goto(URL)
        await mpage.wait_for_timeout(2500)
        await shot(mpage, "mobile-dark")

        # для баннера: светлая главная, норма, без шапки уведомлений
        await page.click("#themeBtn")
        await page.wait_for_timeout(300)
        await shot(page, "_hero")
        await b.close()


if __name__ == "__main__":
    asyncio.run(main())
