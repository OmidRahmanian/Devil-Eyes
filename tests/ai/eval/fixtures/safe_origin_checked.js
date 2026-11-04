// Payment frame messages (lab fixture, origin checked)
const TRUSTED = "https://pay.example.com";
window.addEventListener("message", (event) => {
  if (event.origin !== TRUSTED) return;
  document.getElementById("status").textContent = String(event.data.status);
});
