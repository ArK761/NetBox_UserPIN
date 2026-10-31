// node render.js <input.html> <output.pdf> <footer text>  (uses the Chromium that comes with Playwright)
const { chromium } = require('playwright');
(async () => {
  const [input, output, foot] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('file://' + input);
  await page.pdf({
    path: output, format: 'A4', printBackground: true, displayHeaderFooter: true,
    headerTemplate: '<span></span>',
    footerTemplate: '<div style="width:100%;font-size:7.5px;color:#667;padding:0 16mm;display:flex;justify-content:space-between;font-family:DejaVu Sans,sans-serif"><span>' + foot + '</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
    margin: { top: '18mm', bottom: '20mm', left: '16mm', right: '16mm' },
  });
  await browser.close();
})();
