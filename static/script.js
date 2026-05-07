function analyze() {
    let url = document.getElementById("url").value;

    fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
        .then(res => res.json())
        .then(data => {
            document.getElementById("result").innerText =
                JSON.stringify(data, null, 2);
        });
}