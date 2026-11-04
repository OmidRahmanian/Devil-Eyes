// Embedded widget bridge (lab fixture)
window.addEventListener("message", function (event) {
  var command = event.data;
  if (command && command.run) {
    eval(command.run);
  }
});
