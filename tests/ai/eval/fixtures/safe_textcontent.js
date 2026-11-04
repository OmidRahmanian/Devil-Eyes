// Greeting banner (lab fixture, safe)
function greet() {
  const name = new URLSearchParams(location.search).get("name") || "guest";
  document.getElementById("greeting").textContent = "Hello, " + name;
}
greet();
