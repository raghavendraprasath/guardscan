import { chromium } from "playwright";
import path from "path";
import fs from "fs";
import { execFileSync } from "child_process";

const OUT = path.resolve("..", "docs", "screenshots");
fs.mkdirSync(OUT, { recursive: true });

async function clickExample(page: import("playwright").Page, label: string) {
  await page
    .locator("button")
    .filter({ has: page.locator("span", { hasText: label }) })
    .first()
    .click();
}

async function shot(page: import("playwright").Page, name: string) {
  const png = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: png, fullPage: false });
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });

  await page.goto("http://localhost:3000/", { waitUntil: "networkidle" });
  await page.waitForTimeout(600);
  await shot(page, "01-home");

  const toggle = page.getByRole("switch");
  if ((await toggle.getAttribute("aria-checked")) === "true") {
    await toggle.click();
  }

  await page.getByRole("button", { name: "Scan" }).click();
  await page.getByText("Findings").first().waitFor({ timeout: 15000 });
  await page.waitForTimeout(800);
  await shot(page, "02-vault");

  await clickExample(page, "Hardened AMM");
  await page.waitForTimeout(300);
  await page.getByRole("button", { name: "Scan" }).click();
  await page.getByText("Nothing matched GuardScan").waitFor({ timeout: 15000 });
  await page.waitForTimeout(500);
  await shot(page, "03-hardened");

  await clickExample(page, "Vulnerable AMM");
  await page.waitForTimeout(300);
  await page.getByRole("button", { name: "Scan" }).click();
  await page.getByText("Findings").first().waitFor({ timeout: 15000 });
  await page.waitForTimeout(800);
  await shot(page, "04-amm");

  await browser.close();

  // Compress PNGs → the JPEG names used by the README
  execFileSync(
    "python",
    [
      "-c",
      `
from pathlib import Path
from PIL import Image
src = Path(r"${OUT.replace(/\\/g, "\\\\")}")
mapping = {
  "01-home.png": "scanner-home.jpg",
  "02-vault.png": "vault-findings.jpg",
  "03-hardened.png": "hardened-amm-clean.jpg",
  "04-amm.png": "amm-findings.jpg",
}
for a, b in mapping.items():
  img = Image.open(src / a).convert("RGB")
  if img.width > 1400:
    r = 1400 / img.width
    img = img.resize((1400, int(img.height * r)), Image.Resampling.LANCZOS)
  img.save(src / b, "JPEG", quality=82, optimize=True, progressive=True)
  (src / a).unlink()
  print(b, (src / b).stat().st_size // 1024, "KB")
`,
    ],
    { stdio: "inherit" },
  );

  console.log("updated README screenshots in", OUT);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
