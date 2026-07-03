document.addEventListener("DOMContentLoaded", function () {
  var gaugeFill = document.querySelector(".gauge-fill");
  if (gaugeFill) {
    var score = parseFloat(gaugeFill.dataset.score || "0");
    var radius = parseFloat(gaugeFill.getAttribute("r"));
    var circumference = 2 * Math.PI * radius;
    var offset = circumference - (score / 100) * circumference;

    gaugeFill.style.strokeDasharray = circumference;
    gaugeFill.style.strokeDashoffset = circumference; // start empty
    requestAnimationFrame(function () {
      gaugeFill.style.strokeDashoffset = offset;
    });
  }

  // Autofill demo phishing sample on dashboard for quick testing
  var demoBtn = document.getElementById("load-demo");
  if (demoBtn) {
    demoBtn.addEventListener("click", function () {
      document.getElementById("sender").value = "IT Support <it-support@secure-login-alerts.tk>";
      document.getElementById("subject").value = "URGENT: Your account will be suspended";
      document.getElementById("body").value =
        "Dear Customer,\n\nWe detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your identity immediately.\n\nClick here to confirm your identity: http://account-verify-secure.tk/login\n\nFailure to act now may result in permanent suspension.\n\nThank you,\nSecurity Team";
    });
  }
});
