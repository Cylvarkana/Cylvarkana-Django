document.addEventListener("DOMContentLoaded", function() {
    const flickeringText = document.getElementById('flickering-text');

    // Function to apply a single flicker with reduced likelihood
    function applyFlicker() {
      // Random chance for the flicker to occur (e.g., 25% chance)
      if (Math.random() < 0.25) {
        const flickerDuration = Math.random() * 200 + 100;
        const flickerOpacity = Math.random() * 0.5;

        // Apply flicker effect
        flickeringText.style.transition = `opacity ${flickerDuration}ms`;
        flickeringText.style.opacity = flickerOpacity;

        // Reset opacity to between 0.8 and 1 after flicker
        setTimeout(() => {
          flickeringText.style.opacity = Math.random() * 0.2 + 0.8;

          // Random chance for a second flicker (e.g., 10% chance)
          if (Math.random() < 0.10) {
            // Delay the second flicker slightly to make it noticeable
            setTimeout(() => {
              const secondFlickerDuration = Math.random() * 200 + 100;
              const secondFlickerOpacity = Math.random() * 0.5;

              // Apply second flicker effect
              flickeringText.style.transition = `opacity ${secondFlickerDuration}ms`;
              flickeringText.style.opacity = secondFlickerOpacity;

              // Reset opacity after second flicker
              setTimeout(() => {
                flickeringText.style.opacity = Math.random() * 0.2 + 0.8;
              }, secondFlickerDuration);
            }, flickerDuration / 2); // Delay for second flicker to be noticeable
          }
        }, flickerDuration);
      }
    }

    // Function to start the flicker interval with random timing
    function startFlickerInterval() {
      setInterval(applyFlicker, 1000);
    }

    // Start the flicker interval
    startFlickerInterval();
});
