// ================================================
// PhishGuard - URL Classification Dashboard
// ================================================

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("urlForm");
    const urlInput = document.getElementById("urlInput");
    const checkButton = document.getElementById("checkButton");
    const buttonText = document.getElementById("buttonText");

    const resultSection = document.getElementById("resultSection");
    const resultShield = document.getElementById("resultShield");
    const resultTitle = document.getElementById("resultTitle");
    const resultClass = document.getElementById("resultClass");
    const resultUrl = document.getElementById("resultUrl");
    const resultEyebrow = document.getElementById("resultEyebrow");
    const confidenceValue = document.getElementById("confidenceValue");
    const probabilityList = document.getElementById("probabilityList");
    const errorMessage = document.getElementById("errorMessage");

    const menuToggle = document.getElementById("menuToggle");
    const navLinks = document.querySelector(".nav-links");

    const classOrder = [
        "Benign",
        "Defacement",
        "Malware",
        "Phishing"
    ];

    const classColors = {
        Benign: "benign-fill",
        Defacement: "defacement-fill",
        Malware: "malware-fill",
        Phishing: "phishing-fill"
    };

    // ---------------------------------------------
    // Mobile Navigation
    // ---------------------------------------------

    menuToggle.addEventListener("click", () => {
        const isOpen = navLinks.classList.toggle("open");

        menuToggle.setAttribute("aria-expanded", String(isOpen));
    });

    navLinks.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", () => {
            navLinks.classList.remove("open");
            menuToggle.setAttribute("aria-expanded", "false");
        });
    });

    // ---------------------------------------------
    // Show Error Message
    // ---------------------------------------------

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.hidden = false;
    }

    function clearError() {
        errorMessage.textContent = "";
        errorMessage.hidden = true;
    }

    // ---------------------------------------------
    // Loading State
    // ---------------------------------------------

    function setLoading(loading) {
        checkButton.disabled = loading;
        urlInput.disabled = loading;

        buttonText.textContent = loading
            ? "Analyzing..."
            : "Check Now";
    }

    // ---------------------------------------------
    // Class-specific Result Appearance
    // ---------------------------------------------

    function updateResultAppearance(predictedClass) {
        const isBenign = predictedClass === "Benign";

        resultTitle.textContent = isBenign
            ? "Safe URL!"
            : "Potentially Unsafe!";

        resultEyebrow.textContent = isBenign
            ? "SECURITY ANALYSIS COMPLETE"
            : "SECURITY RISK DETECTED";

        // Keep the shield green for Benign and red for threats.
        resultShield.style.color = isBenign ? "#16a34a" : "#dc2626";

        resultClass.textContent = predictedClass;
    }

    // ---------------------------------------------
    // Display Real Model Probabilities
    // ---------------------------------------------

    function renderProbabilities(probabilities) {
        probabilityList.replaceChildren();

        classOrder.forEach((className) => {
            const rawProbability = probabilities[className];
            const probability = Number(rawProbability);

            const validProbability =
                rawProbability !== undefined &&
                rawProbability !== null &&
                Number.isFinite(probability);

            const value = validProbability
                ? Math.max(0, Math.min(100, probability))
                : 0;

            const row = document.createElement("div");
            row.className = "probability-row";

            const label = document.createElement("span");
            label.textContent = className;

            const track = document.createElement("div");
            track.className = "progress-track";

            const fill = document.createElement("div");
            fill.className = `progress-fill ${classColors[className]}`;
            fill.setAttribute("role", "progressbar");
            fill.setAttribute("aria-label", `${className} probability`);
            fill.setAttribute("aria-valuemin", "0");
            fill.setAttribute("aria-valuemax", "100");
            fill.setAttribute("aria-valuenow", String(value));
            fill.style.width = `${value}%`;

            track.appendChild(fill);

            const percentage = document.createElement("strong");
            percentage.textContent = validProbability
                ? `${probability.toFixed(2)}%`
                : "N/A";

            row.append(label, track, percentage);
            probabilityList.appendChild(row);
        });
    }

    // ---------------------------------------------
    // Display Prediction Result
    // ---------------------------------------------

    function displayResult(result) {
        const predictedClass = result.class || "Unknown";

        resultSection.dataset.class = predictedClass;

        updateResultAppearance(predictedClass);

        resultUrl.textContent = result.url || "";

        if (result.confidence !== undefined &&
            Number.isFinite(Number(result.confidence))) {
            confidenceValue.textContent =
                `${Number(result.confidence).toFixed(2)}%`;
        } else {
            confidenceValue.textContent = "N/A";
        }

        const probabilities = result.probabilities || {};
        renderProbabilities(probabilities);

        resultSection.hidden = false;

        // Bring the result into view after the API responds.
        requestAnimationFrame(() => {
            resultSection.scrollIntoView({
                behavior: "smooth",
                block: "nearest"
            });
        });
    }

    // ---------------------------------------------
    // Submit URL to FastAPI
    // ---------------------------------------------

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        clearError();

        const url = urlInput.value.trim();

        if (!url) {
            showError("Please enter a URL to analyze.");
            urlInput.focus();
            return;
        }

        // Require a valid URL format before sending it.
        let parsedUrl;

        try {
            const normalizedUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(url)
                ? url
                : `https://${url}`;

            parsedUrl = new URL(normalizedUrl);

            if (
                !["http:", "https:"].includes(parsedUrl.protocol) ||
                !parsedUrl.hostname ||
                !parsedUrl.hostname.includes(".")
            ) {
                throw new Error("Invalid website URL.");
            }
        } catch {
            showError(
                "Please enter a valid website URL, such as https://example.com."
            );
            urlInput.focus();
            return;
        }

        setLoading(true);

        try {
            // Relative API path works when the UI and API
            // are served from the same FastAPI application.
            const response = await fetch("/predict", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: url
                })
            });

            let data;

            try {
                data = await response.json();
            } catch {
                throw new Error(
                    "The server returned an invalid response. Please try again."
                );
            }

            if (!response.ok) {
                const detail = data.detail;

                const message = Array.isArray(detail)
                    ? detail.map(item => item.msg || "Invalid input").join(", ")
                    : typeof detail === "string"
                        ? detail
                        : "Unable to analyze this URL.";

                throw new Error(message);
            }

            if (data.status !== "success" || !data.result) {
                throw new Error(
                    "The server did not return a valid prediction."
                );
            }

            displayResult(data.result);

        } catch (error) {
            showError(
                error.message ||
                "Unable to connect to the API. Please check that FastAPI is running."
            );
        } finally {
            setLoading(false);
        }
    });
});