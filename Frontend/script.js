"use strict";

const API_URL = "https://phising-detector-9k4h.onrender.com/predict";

const analyzeBtn = document.getElementById("analyzeBtn");
const urlInput = document.getElementById("urlInput");
const loader = document.getElementById("loader");
const loaderText = document.getElementById("loaderText");
const resultSection = document.getElementById("resultSection");
const predictionLabel = document.getElementById("predictionLabel");
const confScore = document.getElementById("confScore");
const gauge = document.getElementById("gauge");

analyzeBtn.addEventListener("click", async (e) => {
    e.preventDefault();  

    const url = urlInput.value.trim();

    if (!url) { alert("Please enter a URL"); return; }
    if (!isValidURL(url)) { alert("Invalid URL (must include http/https)"); return; }

    resetUI();
    showLoader("Connecting to AI model...");

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Server error");

        showLoader("Analyzing features...");

        setTimeout(() => {
            hideLoader();
            showResults();
            updateResultsUI(data);
        }, 800);

    } catch (err) {
        hideLoader();
        console.error(err);
        alert("Backend not running or API error: " + err.message);
    }
});

function resetUI() {
    resultSection.classList.add("hidden");
    gauge.style.width = "0%";
}

function showLoader(msg) {
    loaderText.innerText = msg;
    loader.classList.remove("hidden");
}

function hideLoader() {
    loader.classList.add("hidden");
}

function showResults() {
    resultSection.classList.remove("hidden");
}

function updateResultsUI(data) {
    const probability = data.probability ?? data.confidence ?? 0;
    const prediction = (data.prediction ?? "").toLowerCase();

    confScore.innerText = probability.toFixed(2) + "%";
    gauge.style.width = probability + "%";

    if (prediction === "phishing") {
        predictionLabel.innerText = "⚠️ DANGER: PHISHING DETECTED";
        predictionLabel.style.color = "var(--danger)";
        gauge.style.backgroundColor = "var(--danger)";
    } else {
        predictionLabel.innerText = "✅ VERIFIED: SAFE LINK";
        predictionLabel.style.color = "var(--primary)";
        gauge.style.backgroundColor = "var(--primary)";
    }
}

function isValidURL(str) {
    try { new URL(str); return true; }
    catch { return false; }
}

urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        e.preventDefault();   
        analyzeBtn.click();
    }
});