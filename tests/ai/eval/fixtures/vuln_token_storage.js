// API client (lab fixture)
async function login(user, password) {
  const response = await fetch("/api/v1/session", { method: "POST", body: JSON.stringify({ user, password }) });
  const data = await response.json();
  localStorage.setItem("access_token", data.access_token);
  return data;
}
function authHeaders() {
  return { Authorization: "Bearer " + localStorage.getItem("access_token") };
}
