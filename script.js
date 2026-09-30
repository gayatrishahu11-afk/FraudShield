/* ============================================================
   FRAUDSHIELD
   SINGLE WORKING SCRIPT
   ============================================================ */

let currentMode = "message";

let fraudCases = JSON.parse(
    localStorage.getItem("fraudShieldCases") || "[]"
);


/* ============================================================
   MODE SELECTION
   ============================================================ */

function selectMode(mode, button) {

    currentMode = mode;
    window.currentMode = mode;

    const sections = [
        "messageInput",
        "urlInput",
        "upiInput",
        "fileInput",
        "imageInput",
        "voiceInput"
    ];

    sections.forEach(id => {
        const el = document.getElementById(id);

        if (el) {
            el.style.display = "none";
        }
    });

    document
        .querySelectorAll(".mode-btn, .mode-card")
        .forEach(el => {
            el.classList.remove("active");
        });

    if (button) {
        button.classList.add("active");
    }

    const inputMap = {
        message: "messageInput",
        url: "urlInput",
        upi: "upiInput",
        pdf: "fileInput",
        image: "imageInput",
        voice: "voiceInput"
    };

    const selected = document.getElementById(
        inputMap[mode]
    );

    if (selected) {
        selected.style.display = "block";
    }

    const titles = {
        message: "Analyze Suspicious Message",
        url: "Analyze Suspicious URL",
        upi: "Analyze UPI Transaction",
        pdf: "Analyze Suspicious PDF",
        image: "Analyze Screenshot / Image",
        voice: "Analyze Voice / Audio"
    };

    const title = document.getElementById("modeTitle");

    if (title) {
        title.textContent =
            titles[mode] || "Analyze Content";
    }
}


/* ============================================================
   DEMO
   ============================================================ */

function loadDemo() {

    const messageBox =
        document.getElementById("messageText");

    if (!messageBox) {
        alert("Message input not found.");
        return;
    }

    const button =
        document.querySelector(
            '.mode-btn[onclick*="message"]'
        );

    selectMode("message", button);

    messageBox.value =
        "URGENT! Your account will be BLOCKED today. " +
        "Complete KYC verification immediately at " +
        "http://secure-kyc-demo.example/verify. " +
        "Enter your OTP, PIN and CVV to avoid account suspension. " +
        "Claim your cashback reward now!";

    messageBox.focus();

    /*
       Automatically analyze demo
    */
    analyzeRisk();
}


/* ============================================================
   MESSAGE ANALYZER
   ============================================================ */

function analyzeMessage(text) {

    const message = text.toLowerCase();

    let score = 0;
    let signals = [];
    let reasons = [];

    const keywords = {
        urgent: 8,
        immediately: 8,
        verify: 6,
        verification: 6,
        kyc: 10,
        blocked: 10,
        suspend: 10,
        suspended: 10,
        account: 4,
        bank: 5,
        click: 7,
        reward: 8,
        cashback: 8,
        refund: 8,
        claim: 6,
        otp: 20,
        pin: 20,
        cvv: 20,
        password: 15,
        payment: 6,
        money: 6,
        prize: 8,
        lottery: 10
    };

    Object.entries(keywords).forEach(
        ([keyword, weight]) => {

            if (message.includes(keyword)) {

                score += weight;

                signals.push(
                    keyword.toUpperCase()
                );

                reasons.push(
                    `Suspicious keyword detected: ${keyword}`
                );
            }
        }
    );


    /* URL */

    if (/https?:\/\/|www\./i.test(text)) {

        score += 20;

        signals.push("URL");

        reasons.push(
            "Message contains an external link."
        );
    }


    /* Urgency */

    if (
        /urgent|immediately|now|today|within.*minute|quickly/i
            .test(text)
    ) {

        score += 15;

        signals.push("URGENCY");

        reasons.push(
            "Urgency or pressure language detected."
        );
    }


    /* Sensitive information */

    if (
        /otp|pin|password|cvv|card number|account number/i
            .test(text)
    ) {

        score += 20;

        signals.push("SENSITIVE DATA");

        reasons.push(
            "Message references sensitive authentication or financial information."
        );
    }


    /* Account threat */

    if (
        /blocked|suspend|suspended|deactivate|close.*account/i
            .test(text)
    ) {

        score += 15;

        signals.push("ACCOUNT THREAT");

        reasons.push(
            "Account restriction or suspension language detected."
        );
    }


    /* Money */

    if (
        /payment|pay|transfer|money|refund|cashback|reward|prize/i
            .test(text)
    ) {

        score += 10;

        signals.push("FINANCIAL ACTION");

        reasons.push(
            "Financial or reward-related action detected."
        );
    }


    /* Excessive ! */

    const exclamation =
        (text.match(/!/g) || []).length;

    if (exclamation >= 3) {

        score += 5;

        signals.push("EXCESSIVE SYMBOLS");

        reasons.push(
            "Message contains excessive exclamation marks."
        );
    }


    return {
        score: Math.min(score, 100),
        signals: [...new Set(signals)],
        reasons: [...new Set(reasons)]
    };
}


/* ============================================================
   URL ANALYZER
   ============================================================ */

function analyzeURL(url) {

    let score = 0;
    let signals = [];
    let reasons = [];

    let parsed;

    try {

        parsed = new URL(url);

    } catch {

        return {
            score: 60,
            signals: ["INVALID URL"],
            reasons: [
                "The entered URL is not in a valid format."
            ]
        };
    }


    /* HTTP */

    if (parsed.protocol === "http:") {

        score += 20;

        signals.push("HTTP");

        reasons.push(
            "URL does not use HTTPS."
        );
    }


    /* Suspicious words */

    const suspiciousWords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "bank",
        "kyc",
        "update",
        "claim",
        "reward",
        "prize",
        "free",
        "otp",
        "password",
        "urgent",
        "confirm"
    ];

    suspiciousWords.forEach(word => {

        if (
            url.toLowerCase().includes(word)
        ) {

            score += 8;

            signals.push(
                word.toUpperCase()
            );

            reasons.push(
                `Suspicious URL keyword detected: ${word}`
            );
        }
    });


    /* IP address */

    if (
        /^https?:\/\/\d{1,3}(\.\d{1,3}){3}/i
            .test(url)
    ) {

        score += 20;

        signals.push("IP ADDRESS");

        reasons.push(
            "URL uses an IP address instead of a domain."
        );
    }


    /* @ */

    if (url.includes("@")) {

        score += 20;

        signals.push("@ SYMBOL");

        reasons.push(
            "URL contains an @ symbol."
        );
    }


    /* Too many hyphens */

    const hyphens =
        (url.match(/-/g) || []).length;

    if (hyphens >= 3) {

        score += 10;

        signals.push("MULTIPLE HYPHENS");

        reasons.push(
            "URL contains multiple hyphens."
        );
    }


    /* Long URL */

    if (url.length > 100) {

        score += 10;

        signals.push("LONG URL");

        reasons.push(
            "URL is unusually long."
        );
    }


    /* Shortener */

    if (
        /bit\.ly|tinyurl|t\.co|shorturl|goo\.gl/i
            .test(url)
    ) {

        score += 15;

        signals.push("SHORTENED URL");

        reasons.push(
            "URL appears to use a URL shortening service."
        );
    }


    return {
        score: Math.min(score, 100),
        signals: [...new Set(signals)],
        reasons: [...new Set(reasons)],
        url
    };
}


/* ============================================================
   UPI ANALYZER
   ============================================================ */

function analyzeUPI(upi, amount) {

    let score = 0;
    let signals = [];
    let reasons = [];

    const id = upi.trim().toLowerCase();

    if (!id.includes("@")) {

        score += 30;

        signals.push("INVALID UPI");

        reasons.push(
            "UPI ID does not contain the expected @ separator."
        );
    }


    const suspiciousWords = [
        "refund",
        "reward",
        "cashback",
        "prize",
        "lottery",
        "offer",
        "verify",
        "kyc",
        "urgent",
        "claim",
        "payment"
    ];

    suspiciousWords.forEach(word => {

        if (id.includes(word)) {

            score += 12;

            signals.push(
                word.toUpperCase()
            );

            reasons.push(
                `Suspicious UPI keyword detected: ${word}`
            );
        }
    });


    const value =
        Number(amount) || 0;


    if (value >= 50000) {

        score += 30;

        signals.push("HIGH AMOUNT");

        reasons.push(
            "Transaction amount is very high."
        );

    } else if (value >= 10000) {

        score += 20;

        signals.push("ELEVATED AMOUNT");

        reasons.push(
            "Transaction amount is relatively high."
        );

    } else if (value >= 5000) {

        score += 10;

        signals.push("AMOUNT");

        reasons.push(
            "Transaction amount is above the basic threshold."
        );
    }


    return {
        score: Math.min(score, 100),
        signals: [...new Set(signals)],
        reasons: [...new Set(reasons)],
        upi: upi,
        amount: value
    };
}


/* ============================================================
   PDF ANALYZER
   ============================================================ */

function analyzeFile() {

    const input =
        document.getElementById("uploadedFile");

    if (!input || !input.files.length) {

        return {
            score: 0,
            signals: ["NO FILE"],
            reasons: [
                "No PDF was selected."
            ]
        };
    }

    const file = input.files[0];

    let score = 10;
    let signals = ["PDF FILE"];
    let reasons = [
        "PDF uploaded for risk assessment."
    ];

    const name =
        file.name.toLowerCase();


    const words = [
        "otp",
        "kyc",
        "refund",
        "payment",
        "urgent",
        "verify",
        "reward",
        "prize",
        "bank"
    ];

    words.forEach(word => {

        if (name.includes(word)) {

            score += 10;

            signals.push(
                word.toUpperCase()
            );

            reasons.push(
                `Suspicious filename keyword detected: ${word}`
            );
        }
    });


    if (file.size > 5 * 1024 * 1024) {

        score += 5;

        signals.push("LARGE FILE");

        reasons.push(
            "Uploaded file is relatively large."
        );
    }


    return {
        score: Math.min(score, 100),
        signals: [...new Set(signals)],
        reasons: [...new Set(reasons)],
        fileName: file.name,
        fileType: file.type
    };
}


/* ============================================================
   IMAGE ANALYZER
   ============================================================ */

function analyzeImage() {

    const input =
        document.getElementById("imageFile");

    if (!input || !input.files.length) {

        return {
            score: 0,
            signals: ["NO IMAGE"],
            reasons: [
                "No image was selected."
            ]
        };
    }

    const file = input.files[0];

    let score = 10;

    let signals = ["IMAGE FILE"];

    let reasons = [
        "Image uploaded for suspicious-content assessment."
    ];

    const name =
        file.name.toLowerCase();

    const words = [
        "otp",
        "kyc",
        "bank",
        "payment",
        "refund",
        "verify",
        "urgent",
        "reward"
    ];

    words.forEach(word => {

        if (name.includes(word)) {

            score += 10;

            signals.push(
                word.toUpperCase()
            );

            reasons.push(
                `Suspicious image filename keyword detected: ${word}`
            );
        }
    });


    return {
        score: Math.min(score, 100),
        signals: [...new Set(signals)],
        reasons: [...new Set(reasons)],
        fileName: file.name,
        fileType: file.type
    };
}


/* ============================================================
   VOICE ANALYZER
   ============================================================ */

function analyzeVoice() {

    const input =
        document.getElementById("voiceFile");

    if (!input || !input.files.length) {

        return {
            score: 0,
            signals: ["NO AUDIO"],
            reasons: [
                "No voice recording was selected."
            ]
        };
    }

    const file = input.files[0];

    let score = 10;

    let signals = ["AUDIO FILE"];

    let reasons = [
        "Voice recording uploaded for risk assessment."
    ];

    const name =
        file.name.toLowerCase();

    const words = [
        "otp",
        "kyc",
        "bank",
        "payment",
        "urgent",
        "verify",
        "refund",
        "reward"
    ];

    words.forEach(word => {

        if (name.includes(word)) {

            score += 10;

            signals.push(
                word.toUpperCase()
            );

            reasons.push(
                `Suspicious audio filename keyword detected: ${word}`
            );
        }
    });


    return {
        score: Math.min(score, 100),
        signals: [...new Set(signals)],
        reasons: [...new Set(reasons)],
        fileName: file.name,
        fileType: file.type
    };
}


/* ============================================================
   RISK LEVEL
   ============================================================ */

function getRiskLevel(score) {

    if (score >= 70) {
        return "HIGH";
    }

    if (score >= 40) {
        return "MEDIUM";
    }

    return "LOW";
}


/* ============================================================
   MAIN ANALYZER
   ============================================================ */

function analyzeRisk() {

    window.currentMode = currentMode;

    let result = null;


    if (currentMode === "message") {

        const input =
            document.getElementById("messageText");

        if (!input || !input.value.trim()) {

            alert(
                "Please enter a message first."
            );

            return;
        }

        result =
            analyzeMessage(
                input.value.trim()
            );
    }


    else if (currentMode === "url") {

        const input =
            document.getElementById("urlText");

        if (!input || !input.value.trim()) {

            alert(
                "Please enter a URL first."
            );

            return;
        }

        result =
            analyzeURL(
                input.value.trim()
            );
    }


    else if (currentMode === "upi") {

        const upi =
            document.getElementById("upiText");

        const amount =
            document.getElementById("upiAmount");

        if (!upi || !upi.value.trim()) {

            alert(
                "Please enter a UPI ID first."
            );

            return;
        }

        result =
            analyzeUPI(
                upi.value,
                amount ? amount.value : 0
            );
    }


    else if (currentMode === "pdf") {

        result = analyzeFile();
    }


    else if (currentMode === "image") {

        result = analyzeImage();
    }


    else if (currentMode === "voice") {

        result = analyzeVoice();
    }


    else {

        alert(
            "Please select an analysis mode."
        );

        return;
    }


    displayResult(result);
}


/* ============================================================
   DISPLAY RESULT
   ============================================================ */

function displayResult(result) {

    const score =
        Math.round(
            Math.max(
                0,
                Math.min(100, result.score || 0)
            )
        );

    const risk =
        getRiskLevel(score);


    /* SCORE */

    const scoreEl =
        document.getElementById("score");

    if (scoreEl) {
        scoreEl.textContent = score;
    }


    /* RESULT STATUS */

    const status =
        document.getElementById("resultStatus");

    if (status) {

        status.textContent =
            `${risk} RISK`;

        status.className =
            `result-status ${risk.toLowerCase()}`;
    }


    /* HERO SCORE */

    const heroScore =
        document.getElementById("heroScore");

    if (heroScore) {
        heroScore.textContent = score;
    }


    /* HERO RISK */

    const heroRisk =
        document.getElementById("heroRiskLevel");

    if (heroRisk) {
        heroRisk.textContent =
            `${risk} RISK`;
    }


    /* RESULT BAR */

    const resultFill =
        document.getElementById("resultRiskFill");

    if (resultFill) {
        resultFill.style.width =
            `${score}%`;
    }


    /* HERO BAR */

    const heroFill =
        document.getElementById("heroRiskFill");

    if (heroFill) {
        heroFill.style.width =
            `${score}%`;
    }


    /* SCORE MESSAGE */

    const message =
        document.getElementById("scoreMessage");

    if (message) {

        if (score >= 70) {

            message.textContent =
                "Multiple high-risk indicators were detected. Review this case carefully.";

        } else if (score >= 40) {

            message.textContent =
                "Some suspicious indicators were detected. Additional verification is recommended.";

        } else {

            message.textContent =
                "Only a limited number of suspicious indicators were detected.";
        }
    }


    /* SIGNAL COUNT */

    const signalCount =
        document.getElementById("signalCount");

    if (signalCount) {

        signalCount.textContent =
            result.signals.length;
    }


    /* SIGNAL LIST */

    const signalList =
        document.getElementById("signalsList");

    if (signalList) {

        signalList.innerHTML = "";

        if (result.signals.length === 0) {

            signalList.innerHTML =
                "<div class='signal-item'>No major signals detected.</div>";

        } else {

            result.signals.forEach(signal => {

                const div =
                    document.createElement("div");

                div.className =
                    "signal-item";

                div.innerHTML =
                    `<span>${escapeHTML(signal)}</span>`;

                signalList.appendChild(div);
            });
        }
    }


    /* REASONS */

    const reasons =
        document.getElementById("reasons");

    if (reasons) {

        reasons.innerHTML = "";

        if (result.reasons.length === 0) {

            reasons.innerHTML =
                "<li>No strong suspicious indicator detected.</li>";

        } else {

            result.reasons.forEach(reason => {

                const li =
                    document.createElement("li");

                li.textContent = reason;

                reasons.appendChild(li);
            });
        }
    }


    /* BREAKDOWN */

    const breakdown =
        document.getElementById(
            "riskBreakdownList"
        );

    if (breakdown) {

        breakdown.innerHTML = "";

        result.signals.forEach(signal => {

            const item =
                document.createElement("div");

            item.className =
                "breakdown-item";

            item.innerHTML = `
                <span>${escapeHTML(signal)}</span>
                <strong>DETECTED</strong>
            `;

            breakdown.appendChild(item);
        });

        if (result.signals.length === 0) {

            breakdown.innerHTML = `
                <div class="breakdown-item">
                    <span>No suspicious indicators</span>
                    <strong>0</strong>
                </div>
            `;
        }
    }


    /* BREAKDOWN TOTAL */

    const total =
        document.getElementById(
            "breakdownTotal"
        );

    if (total) {
        total.textContent =
            `${score}/100`;
    }


    /* EXPLANATION */

    displayRiskExplanation(result);


    /* DSA */

    processDSAResult(result);


    /* NETWORK */

    generateFraudNetwork(result);


    /* HISTORY */

    saveFraudCase(result);


    /* RESULT SCROLL */

    const results =
        document.getElementById("results");

    if (results) {

        results.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }


    if (
        typeof lucide !== "undefined"
    ) {

        lucide.createIcons();
    }
}


/* ============================================================
   ESCAPE HTML
   ============================================================ */

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* ============================================================
   RISK EXPLANATION
   ============================================================ */

function displayRiskExplanation(result) {

    let box =
        document.getElementById(
            "riskExplanation"
        );

    if (!box) {

        const results =
            document.getElementById(
                "results"
            );

        if (!results) return;

        const wrapper =
            document.createElement("div");

        wrapper.className =
            "risk-explanation-box";

        wrapper.innerHTML = `
            <div class="risk-explanation-header">
                <div>
                    <span class="section-kicker">
                        EXPLAINABLE ANALYSIS
                    </span>

                    <h3>
                        Why This Risk Score?
                    </h3>

                    <p>
                        This is a risk assessment based on
                        detected indicators, not confirmation of fraud.
                    </p>
                </div>
            </div>

            <div
                id="riskExplanation"
                class="risk-explanation-list"
            ></div>
        `;

        results.appendChild(wrapper);

        box =
            document.getElementById(
                "riskExplanation"
            );
    }

    if (!box) return;

    box.innerHTML = "";

    let explanations = [];


    if (result.score >= 70) {

        explanations.push(
            "Multiple suspicious indicators were detected."
        );

    } else if (result.score >= 40) {

        explanations.push(
            "Several indicators require additional verification."
        );

    } else {

        explanations.push(
            "Only limited suspicious indicators were detected."
        );
    }


    result.reasons
        .slice(0, 6)
        .forEach(reason => {

            explanations.push(reason);
        });


    explanations =
        [...new Set(explanations)];


    explanations.forEach(text => {

        const item =
            document.createElement("div");

        item.className =
            "risk-explanation-item";

        item.innerHTML = `
            <div class="risk-explanation-content">
                <h4>Detected Evidence</h4>
                <p>${escapeHTML(text)}</p>
            </div>
        `;

        box.appendChild(item);
    });
}


/* ============================================================
   CASE HISTORY
   ============================================================ */

function saveFraudCase(result) {

    const score =
        Math.round(result.score);

    const risk =
        getRiskLevel(score);

    const caseData = {

        id:
            "FS-" +
            Date.now()
                .toString()
                .slice(-6),

        type:
            currentMode.toUpperCase(),

        score,

        risk,

        signals:
            result.signals || [],

        reasons:
            result.reasons || [],

        time:
            new Date().toLocaleString()
    };


    fraudCases.unshift(caseData);

    fraudCases =
        fraudCases.slice(0, 20);

    localStorage.setItem(
        "fraudShieldCases",
        JSON.stringify(fraudCases)
    );

    renderCaseHistory();
}


function renderCaseHistory() {

    const list =
        document.getElementById(
            "caseHistoryList"
        );

    const count =
        document.getElementById(
            "caseCount"
        );

    if (!list) return;

    if (count) {
        count.textContent =
            fraudCases.length;
    }

    if (fraudCases.length === 0) {

        list.innerHTML = `
            <div class="empty-history">
                <h3>No cases yet</h3>
                <p>
                    Analyze suspicious content to create a case.
                </p>
            </div>
        `;

        return;
    }


    list.innerHTML = "";

    fraudCases.forEach(item => {

        const card =
            document.createElement("div");

        card.className =
            "case-history-item";

        card.innerHTML = `
            <div class="case-main">

                <div class="case-icon">
                    <i data-lucide="shield-alert"></i>
                </div>

                <div class="case-details">
                    <strong>${escapeHTML(item.id)}</strong>
                    <span>${escapeHTML(item.type)}</span>
                    <small>${escapeHTML(item.time)}</small>
                </div>

            </div>

            <div class="case-score">
                <strong>${item.score}</strong>
                <span>/100</span>
            </div>

            <div class="case-risk ${item.risk.toLowerCase()}">
                ${item.risk} Risk
            </div>
        `;

        list.appendChild(card);
    });


    if (
        typeof lucide !== "undefined"
    ) {
        lucide.createIcons();
    }
}


/* ============================================================
   SEARCH CASES
   ============================================================ */

function searchCases() {

    const search =
        document.getElementById(
            "caseSearch"
        );

    const filter =
        document.getElementById(
            "riskFilter"
        );

    if (!search) return;

    const query =
        search.value
            .toLowerCase()
            .trim();

    const selected =
        filter
            ? filter.value.toLowerCase()
            : "all";

    const list =
        document.getElementById(
            "caseHistoryList"
        );

    if (!list) return;


    const filtered =
        fraudCases.filter(item => {

            const matchesText =
                item.id.toLowerCase().includes(query) ||
                item.type.toLowerCase().includes(query) ||
                item.risk.toLowerCase().includes(query);

            const matchesRisk =
                selected === "all" ||
                item.risk.toLowerCase() === selected;

            return matchesText && matchesRisk;
        });


    list.innerHTML = "";


    filtered.forEach(item => {

        const card =
            document.createElement("div");

        card.className =
            "case-history-item";

        card.innerHTML = `
            <div class="case-main">
                <div class="case-icon">
                    <i data-lucide="shield-alert"></i>
                </div>

                <div class="case-details">
                    <strong>${escapeHTML(item.id)}</strong>
                    <span>${escapeHTML(item.type)}</span>
                    <small>${escapeHTML(item.time)}</small>
                </div>
            </div>

            <div class="case-score">
                <strong>${item.score}</strong>
                <span>/100</span>
            </div>

            <div class="case-risk ${item.risk.toLowerCase()}">
                ${item.risk} Risk
            </div>
        `;

        list.appendChild(card);
    });


    if (
        typeof lucide !== "undefined"
    ) {
        lucide.createIcons();
    }
}


/* ============================================================
   CLEAR HISTORY
   ============================================================ */

function clearCaseHistory() {

    if (
        !confirm(
            "Clear all FraudShield case history?"
        )
    ) {
        return;
    }

    fraudCases = [];

    localStorage.removeItem(
        "fraudShieldCases"
    );

    renderCaseHistory();
}


/* ============================================================
   DSA ENGINE
   ============================================================ */


/* ARRAY */

class RiskArray {

    constructor() {
        this.data = [];
    }

    add(value) {
        this.data.push(value);
    }
}


/* STACK */

class RiskStack {

    constructor() {
        this.data = [];
    }

    push(value) {
        this.data.push(value);
    }

    pop() {
        return this.data.pop();
    }
}


/* QUEUE */

class RiskQueue {

    constructor() {
        this.data = [];
    }

    enqueue(value) {
        this.data.push(value);
    }

    dequeue() {
        return this.data.shift();
    }
}


/* LINKED LIST */

class ListNode {

    constructor(value) {
        this.value = value;
        this.next = null;
    }
}

class RiskLinkedList {

    constructor() {
        this.head = null;
    }

    add(value) {

        const node =
            new ListNode(value);

        if (!this.head) {

            this.head = node;
            return;
        }

        let current = this.head;

        while (current.next) {
            current = current.next;
        }

        current.next = node;
    }
}


/* SET */

class RiskSet {

    constructor() {
        this.data = new Set();
    }

    add(value) {
        this.data.add(value);
    }
}


/* HASH TABLE */

class RiskHashTable {

    constructor() {
        this.data = {};
    }

    set(key, value) {
        this.data[key] = value;
    }

    get(key) {
        return this.data[key];
    }
}


/* HEAP */

class RiskHeap {

    constructor() {
        this.data = [];
    }

    insert(value) {

        this.data.push(value);

        this.data.sort(
            (a, b) => b - a
        );
    }

    peek() {
        return this.data[0];
    }
}


/* TRIE */

class TrieNode {

    constructor() {
        this.children = {};
        this.end = false;
    }
}

class RiskTrie {

    constructor() {
        this.root =
            new TrieNode();
    }

    insert(word) {

        let node = this.root;

        for (
            const char of word.toLowerCase()
        ) {

            if (!node.children[char]) {

                node.children[char] =
                    new TrieNode();
            }

            node =
                node.children[char];
        }

        node.end = true;
    }
}


/* ============================================================
   DSA PROCESS
   ============================================================ */

function processDSAResult(result) {

    const array =
        new RiskArray();

    result.signals.forEach(
        signal => array.add(signal)
    );


    const stack =
        new RiskStack();

    result.signals.forEach(
        signal => stack.push(signal)
    );


    const queue =
        new RiskQueue();

    result.signals.forEach(
        signal => queue.enqueue(signal)
    );


    const list =
        new RiskLinkedList();

    result.signals.forEach(
        signal => list.add(signal)
    );


    const set =
        new RiskSet();

    result.signals.forEach(
        signal => set.add(signal)
    );


    const hash =
        new RiskHashTable();

    result.signals.forEach(
        signal =>
            hash.set(signal, true)
    );


    const heap =
        new RiskHeap();

    heap.insert(result.score);


    const trie =
        new RiskTrie();

    result.signals.forEach(
        signal =>
            trie.insert(signal)
    );


    /* DSA UI */

    setDSAText(
        "dsaArray",
        `Elements: ${array.data.length}`
    );

    setDSAText(
        "dsaStack",
        `Top: ${stack.data[stack.data.length - 1] || "Empty"}`
    );

    setDSAText(
        "dsaQueue",
        `Items: ${queue.data.length}`
    );

    setDSAText(
        "dsaLinkedList",
        `Nodes: ${result.signals.length}`
    );

    setDSAText(
        "dsaHash",
        `Keys: ${Object.keys(hash.data).length}`
    );

    setDSAText(
        "dsaHeap",
        `Max Risk: ${heap.peek() || 0}`
    );

    setDSAText(
        "dsaTrie",
        `Keywords: ${result.signals.length}`
    );
}


function setDSAText(id, text) {

    const el =
        document.getElementById(id);

    if (el) {
        el.textContent = text;
    }
}


/* ============================================================
   FRAUD GRAPH
   ============================================================ */

class FraudGraph {

    constructor() {
        this.graph = {};
    }

    addNode(node) {

        if (!this.graph[node]) {
            this.graph[node] = [];
        }
    }

    addEdge(a, b) {

        this.addNode(a);
        this.addNode(b);

        this.graph[a].push(b);
        this.graph[b].push(a);
    }


    bfs(start) {

        if (!this.graph[start]) {
            return [];
        }

        const visited =
            new Set();

        const queue =
            [start];

        const result = [];

        visited.add(start);

        while (queue.length) {

            const node =
                queue.shift();

            result.push(node);

            this.graph[node]
                .forEach(next => {

                    if (!visited.has(next)) {

                        visited.add(next);

                        queue.push(next);
                    }
                });
        }

        return result;
    }


    dfs(start) {

        const visited =
            new Set();

        const result = [];


        const visit = node => {

            if (
                visited.has(node) ||
                !this.graph[node]
            ) {
                return;
            }

            visited.add(node);

            result.push(node);

            this.graph[node]
                .forEach(visit);
        };


        visit(start);

        return result;
    }
}


/* ============================================================
   NETWORK
   ============================================================ */

function generateFraudNetwork(result) {

    const graph =
        new FraudGraph();


    graph.addEdge(
        "CASE",
        "MESSAGE"
    );

    graph.addEdge(
        "CASE",
        "SENDER"
    );


    result.signals
        .slice(0, 5)
        .forEach(signal => {

            graph.addEdge(
                "MESSAGE",
                signal
            );
        });


    const bfs =
        graph.bfs("CASE");

    const dfs =
        graph.dfs("CASE");


    const bfsEl =
        document.getElementById(
            "networkBFS"
        );

    if (bfsEl) {

        bfsEl.textContent =
            bfs.join(" → ");
    }


    const dfsEl =
        document.getElementById(
            "networkDFS"
        );

    if (dfsEl) {

        dfsEl.textContent =
            dfs.join(" → ");
    }


    const nodes =
        document.getElementById(
            "networkNodes"
        );

    if (nodes) {

        nodes.textContent =
            Object.keys(graph.graph).length;
    }


    let edges = 0;

    Object.values(graph.graph)
        .forEach(arr => {
            edges += arr.length;
        });

    edges =
        Math.floor(edges / 2);


    const edgeEl =
        document.getElementById(
            "networkEdges"
        );

    if (edgeEl) {

        edgeEl.textContent =
            edges;
    }


    const status =
        document.getElementById(
            "networkStatus"
        );

    if (status) {

        status.textContent =
            "NETWORK ANALYSIS ACTIVE";
    }


    drawNetwork(graph);
}


/* ============================================================
   SIMPLE NETWORK VISUAL
   ============================================================ */

function drawNetwork(graph) {

    const canvas =
        document.getElementById(
            "fraudNetworkCanvas"
        );

    if (!canvas) return;


    canvas.innerHTML = "";


    Object.keys(graph.graph)
        .forEach((node, index) => {

            const item =
                document.createElement("div");

            item.className =
                "network-node";

            item.textContent =
                node;

            item.style.left =
                `${10 + (index * 16) % 80}%`;

            item.style.top =
                `${25 + (index * 23) % 55}%`;

            canvas.appendChild(item);
        });
}


/* ============================================================
   SCROLL
   ============================================================ */

function scrollToAnalyzer() {

    const el =
        document.getElementById(
            "analyzer"
        );

    if (el) {

        el.scrollIntoView({
            behavior: "smooth"
        });
    }
}


function scrollToDSA() {

    const el =
        document.getElementById(
            "dsa"
        );

    if (el) {

        el.scrollIntoView({
            behavior: "smooth"
        });
    }
}


/* ============================================================
   FILE INPUTS
   ============================================================ */

function setupFileInputs() {

    const pdf =
        document.getElementById(
            "uploadedFile"
        );

    if (pdf) {

        pdf.addEventListener(
            "change",
            function () {

                const file =
                    this.files[0];

                const label =
                    document.getElementById(
                        "uploadedFileName"
                    );

                if (label) {

                    label.textContent =
                        file
                            ? file.name
                            : "No file selected";
                }
            }
        );
    }


    const image =
        document.getElementById(
            "imageFile"
        );

    if (image) {

        image.addEventListener(
            "change",
            function () {

                const file =
                    this.files[0];

                const parent =
                    this.parentElement;

                if (file && parent) {

                    const label =
                        parent.querySelector(
                            "div"
                        );

                    if (label) {
                        label.textContent =
                            file.name;
                    }
                }
            }
        );
    }


    const voice =
        document.getElementById(
            "voiceFile"
        );

    if (voice) {

        voice.addEventListener(
            "change",
            function () {

                const file =
                    this.files[0];

                const parent =
                    this.parentElement;

                if (file && parent) {

                    const label =
                        parent.querySelector(
                            "div"
                        );

                    if (label) {
                        label.textContent =
                            file.name;
                    }
                }
            }
        );
    }
}


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const messageButton =
            document.querySelector(
                '.mode-btn[onclick*="message"]'
            );

        selectMode(
            "message",
            messageButton
        );

        setupFileInputs();

        renderCaseHistory();


        if (
            typeof lucide !== "undefined"
        ) {

            lucide.createIcons();
        }


        console.log(
            "FraudShield initialized successfully."
        );
    }
);


/* ============================================================
   GLOBAL FUNCTIONS
   ============================================================ */

window.selectMode =
    selectMode;

window.loadDemo =
    loadDemo;

window.analyzeRisk =
    analyzeRisk;

window.scrollToAnalyzer =
    scrollToAnalyzer;

window.scrollToDSA =
    scrollToDSA;

window.searchCases =
    searchCases;

window.clearCaseHistory =
    clearCaseHistory;

window.processDSAResult =
    processDSAResult;

window.generateFraudNetwork =
    generateFraudNetwork;

window.displayResult =
    displayResult;
    /* ============================================================
   FRAUDSHIELD - FINAL NAVIGATION / RESULT FIX
   ============================================================ */

function fraudShieldGoTo(id) {

    const section = document.getElementById(id);

    if (!section) {
        console.log("Section not found:", id);
        return;
    }

    const navbar =
        document.querySelector(".navbar");

    const navHeight =
        navbar ? navbar.offsetHeight : 80;

    const position =
        section.getBoundingClientRect().top +
        window.pageYOffset -
        navHeight -
        20;

    window.scrollTo({
        top: Math.max(0, position),
        behavior: "smooth"
    });
}


/* ANALYZER */

window.scrollToAnalyzer = function () {

    fraudShieldGoTo("analyzer");

};


/* NETWORK */

window.scrollToNetwork = function () {

    fraudShieldGoTo("network");

};


/* HISTORY */

window.scrollToHistory = function () {

    fraudShieldGoTo("history");

};


/* DSA */

window.scrollToDSA = function () {

    fraudShieldGoTo("dsa");

};


/* RESULTS */

window.scrollToResults = function () {

    fraudShieldGoTo("results");

};


/* ============================================================
   FORCE RESULT TO SHOW AFTER ANALYSIS
   ============================================================ */

const oldDisplayResult =
    window.displayResult;


/*
   Wait until browser finishes updating result UI,
   then move to Risk Intelligence section.
*/

window.displayResult = function (result) {

    if (typeof oldDisplayResult === "function") {

        oldDisplayResult(result);

    }

    setTimeout(function () {

        fraudShieldGoTo("results");

    }, 300);

};


/* ============================================================
   NAVBAR LINKS
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const links =
            document.querySelectorAll(
                ".nav-links a"
            );

        links.forEach(function (link) {

            link.addEventListener(
                "click",
                function (event) {

                    const href =
                        this.getAttribute("href");

                    if (
                        href &&
                        href.startsWith("#")
                    ) {

                        event.preventDefault();

                        const target =
                            href.substring(1);

                        fraudShieldGoTo(target);

                    }

                }
            );

        });

    }
);


/* ============================================================
   RESULT BUTTON
   ============================================================ */

window.forceShowResult = function () {

    const result =
        document.getElementById("results");

    if (!result) {

        alert(
            "Result section not found in HTML."
        );

        return;
    }

    fraudShieldGoTo("results");

};