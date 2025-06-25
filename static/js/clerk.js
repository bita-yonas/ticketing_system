document.addEventListener("DOMContentLoaded", function () {
  const publishableKey = document.querySelector(
    'meta[name="clerk-publishable-key"]'
  ).content;

  if (!window.Clerk) {
    console.error(
      "Clerk object not found. Make sure the Clerk script is loaded correctly."
    );
    return;
  }

  window.Clerk.load({
    publishableKey: publishableKey,
  })
    .then((clerk) => {
      console.log("Clerk loaded successfully");

      // Get the sign-in button
      const signInButton = document.getElementById("clerkSignInButton");
      if (signInButton) {
        signInButton.disabled = false;
        signInButton.addEventListener("click", () => {
          clerk
            .openSignIn()
            .then((result) => {
              if (result && result.createdSessionId) {
                // Redirect to the callback URL with the session token
                window.location.href =
                  "/clerk-callback?session_token=" + result.createdSessionId;
              }
            })
            .catch((error) => {
              console.error("Sign in error:", error);
            });
        });
      }
    })
    .catch((error) => {
      console.error("Error loading Clerk:", error);
    });
});
