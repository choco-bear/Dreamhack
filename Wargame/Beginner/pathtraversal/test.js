const users = {
  guest: 0,
  admin: 1,
};
function user(evt) {
  document.getElementById("userid").value =
    users[document.getElementById("userid").value];
  return true;
}
window.onload = function () {
  document.getElementById("form").addEventListener("submit", user);
};
