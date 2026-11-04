// Search results page (lab fixture)
function renderQuery() {
  var term = decodeURIComponent(location.hash.slice(1));
  document.getElementById("results-title").innerHTML = "Results for " + term;
}
window.addEventListener("hashchange", renderQuery);
renderQuery();
