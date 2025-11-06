window.onload = () => {
  const synth = window.speechSynthesis;
  const greet = new SpeechSynthesisUtterance(
    "Welcome to Digital Guardian — your cyber protection assistant. Enter URLs and I’ll analyze them."
  );
  greet.lang = "en-IN";
  greet.rate = 0.9;
  setTimeout(() => synth.speak(greet), 1000);
};

document.getElementById("analyzeBtn").onclick = async () => {
  const text = document.getElementById("urlInput").value.trim();
  if (!text) return alert("Please enter at least one URL!");
  const urls = text.split(/\n+/).map(u => u.trim()).filter(u => u);
  if (!urls.length) return alert("No valid URLs found!");

  document.getElementById("loading").classList.remove("hidden");
  document.getElementById("summaryBox").innerHTML = "";
  document.getElementById("resultContainer").innerHTML = "";

  const res = await fetch("/analyze-bulk", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls })
  });
  const data = await res.json();
  document.getElementById("loading").classList.add("hidden");

  const s = data.summary;
  document.getElementById("summaryBox").innerText =
    `Summary: ${s.safe} Safe | ${s.malicious} Malicious | Total ${s.total}`;

  let html = "";
  data.results.forEach(r => {
    const cls = r.status.toLowerCase();
    html += `<div class="result-box ${cls}">
      URL: ${r.url}<br>Status: ${r.status} (${r.confidence}%)<br>Issues: ${r.issues.join("; ")}
    </div>`;
  });
  document.getElementById("resultContainer").innerHTML = html;
};

document.getElementById("exportBtn").onclick = async () => {
  const boxes = document.querySelectorAll("#resultContainer .result-box");
  if (!boxes.length) return alert("No results to export!");
  const results = [];
  boxes.forEach(box => {
    const lines = box.innerText.split("\n");
    results.push({
      url: lines[0].replace("URL: ",""),
      status: lines[1].replace("Status: ","").split(" ")[0],
      confidence: parseInt(lines[1].match(/\((\d+)%\)/)[1]),
      issues: lines[2].replace("Issues: ","").split("; ")
    });
  });
  const res = await fetch("/export-results", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ results })
  });
  const blob = await res.blob();
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "url_analysis_results.html";
  link.click();
};
