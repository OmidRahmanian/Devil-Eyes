// Login completion (lab fixture)
const params = new URLSearchParams(location.search);
function finishLogin() {
  const next = params.get("next");
  location.href = next;
}
document.getElementById("done").addEventListener("click", finishLogin);
