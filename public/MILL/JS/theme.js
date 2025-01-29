    // Check the saved theme preference and apply it
    const theme = localStorage.getItem("theme") || "light"; // Default to light if not set
    if (theme === "dark") {
        document.body.classList.add("dark");
        document.querySelector("#checkbox").checked = true; // Check the toggle
    }

    // Toggle theme on checkbox change
    document.querySelector("#checkbox").addEventListener("change", () => {
        document.body.classList.toggle("dark");
        const currentTheme = document.body.classList.contains("dark") ? "dark" : "light";
        localStorage.setItem("theme", currentTheme);
    });
