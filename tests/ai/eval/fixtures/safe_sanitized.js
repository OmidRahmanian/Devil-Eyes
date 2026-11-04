// Comment preview (lab fixture, sanitized)
function preview(markdownHtml) {
  const clean = DOMPurify.sanitize(markdownHtml, { USE_PROFILES: { html: true } });
  document.getElementById("preview").innerHTML = clean;
}
document.getElementById("comment").addEventListener("input", (e) => preview(render(e.target.value)));
