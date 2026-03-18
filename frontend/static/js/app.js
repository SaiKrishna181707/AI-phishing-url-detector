const form = document.getElementById("predict-form");
const urlInput = document.getElementById("url-input");
const resultCard = document.getElementById("result-card");
const errorCard = document.getElementById("error-card");
const predictionLabel = document.getElementById("prediction-label");
const probabilityPill = document.getElementById("probability-pill");
const explanationText = document.getElementById("explanation-text");
const blacklistValue = document.getElementById("blacklist-value");
const reasonsList = document.getElementById("reasons-list");
const sampleButtons = document.querySelectorAll(".sample-button");

function setResultAppearance(prediction, probability) {
  probabilityPill.textContent =
    prediction === "Safe"
      ? `${Math.round((1 - probability) * 100)}% Safe`
      : `${Math.round(probability * 100)}% Scam`;
  probabilityPill.className = `pill ${prediction === "Scam" ? "scam" : "safe"}`;
}

function renderReasons(reasons) {
  reasonsList.innerHTML = "";
  reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsList.appendChild(item);
  });
}

async function analyzeUrl(url) {
  errorCard.classList.add("hidden");
  resultCard.classList.add("hidden");

  const response = await fetch("/api/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Unable to analyze this URL.");
  }

  const displayPercent =
    payload.prediction === "Safe"
      ? (100 - payload.probability * 100).toFixed(2)
      : (payload.probability * 100).toFixed(2);
  predictionLabel.textContent = `${payload.prediction} · ${displayPercent}%`;
  explanationText.textContent = payload.explanation;
  blacklistValue.textContent = payload.blacklist_match ? "Yes" : "No";
  setResultAppearance(payload.prediction, payload.probability);
  renderReasons(payload.reasons || []);
  resultCard.classList.remove("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await analyzeUrl(urlInput.value);
  } catch (error) {
    errorCard.textContent = error.message;
    errorCard.classList.remove("hidden");
  }
});

sampleButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    urlInput.value = button.dataset.url;
    try {
      await analyzeUrl(button.dataset.url);
    } catch (error) {
      errorCard.textContent = error.message;
      errorCard.classList.remove("hidden");
    }
  });
});
