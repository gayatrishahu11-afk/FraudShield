
/* =========================================================
   FRAUDSHIELD - DSA ENGINE
   Dynamic Fraud Network + DSA Structures
   ========================================================= */


/* =========================================================
   1. SET
   Stores unique fraud indicators
   ========================================================= */

class RiskSet {

    constructor() {
        this.items = new Set();
    }

    add(value) {
        if (value) {
            this.items.add(value);
        }
    }

    clear() {
        this.items.clear();
    }

    getAll() {
        return Array.from(this.items);
    }

    size() {
        return this.items.size;
    }
}


/* =========================================================
   2. STACK
   Stores latest evidence
   ========================================================= */

class EvidenceStack {

    constructor() {
        this.items = [];
    }

    push(value) {
        if (value) {
            this.items.push(value);
        }
    }

    pop() {
        return this.items.pop();
    }

    clear() {
        this.items = [];
    }

    peek() {
        return this.items.length
            ? this.items[this.items.length - 1]
            : null;
    }

    getAll() {
        return [...this.items].reverse();
    }

    size() {
        return this.items.length;
    }
}


/* =========================================================
   3. QUEUE
   Stores cases in processing order
   ========================================================= */

class CaseQueue {

    constructor() {
        this.items = [];
    }

    enqueue(value) {
        if (value) {
            this.items.push(value);
        }
    }

    dequeue() {
        return this.items.shift();
    }

    clear() {
        this.items = [];
    }

    getAll() {
        return [...this.items];
    }

    size() {
        return this.items.length;
    }
}


/* =========================================================
   4. LINKED LIST
   Stores analysis history
   ========================================================= */

class HistoryNode {

    constructor(data) {
        this.data = data;
        this.next = null;
    }
}


class CaseLinkedList {

    constructor() {
        this.head = null;
        this.length = 0;
    }

    add(data) {

        const newNode = new HistoryNode(data);

        if (!this.head) {
            this.head = newNode;
        } else {

            let current = this.head;

            while (current.next) {
                current = current.next;
            }

            current.next = newNode;
        }

        this.length++;
    }

    getAll() {

        const result = [];

        let current = this.head;

        while (current) {
            result.push(current.data);
            current = current.next;
        }

        return result;
    }

    clear() {
        this.head = null;
        this.length = 0;
    }

    size() {
        return this.length;
    }
}


/* =========================================================
   5. HASH TABLE
   Fast lookup of suspicious entities
   ========================================================= */

class FraudHashTable {

    constructor() {
        this.table = new Map();
    }

    set(key, value) {

        if (key) {
            this.table.set(key, value);
        }
    }

    get(key) {
        return this.table.get(key);
    }

    has(key) {
        return this.table.has(key);
    }

    clear() {
        this.table.clear();
    }

    getAll() {
        return Array.from(this.table.entries());
    }

    size() {
        return this.table.size;
    }
}


/* =========================================================
   6. MAX HEAP
   Highest risk case stays at top
   ========================================================= */

class RiskMaxHeap {

    constructor() {
        this.heap = [];
    }

    parent(index) {
        return Math.floor((index - 1) / 2);
    }

    left(index) {
        return index * 2 + 1;
    }

    right(index) {
        return index * 2 + 2;
    }

    swap(a, b) {

        const temp = this.heap[a];

        this.heap[a] = this.heap[b];
        this.heap[b] = temp;
    }

    insert(item) {

        this.heap.push(item);

        let index = this.heap.length - 1;

        while (
            index > 0 &&
            this.heap[this.parent(index)].score < this.heap[index].score
        ) {

            this.swap(index, this.parent(index));

            index = this.parent(index);
        }
    }

    extractMax() {

        if (this.heap.length === 0) {
            return null;
        }

        if (this.heap.length === 1) {
            return this.heap.pop();
        }

        const max = this.heap[0];

        this.heap[0] = this.heap.pop();

        this.heapify(0);

        return max;
    }

    heapify(index) {

        const left = this.left(index);
        const right = this.right(index);

        let largest = index;

        if (
            left < this.heap.length &&
            this.heap[left].score > this.heap[largest].score
        ) {
            largest = left;
        }

        if (
            right < this.heap.length &&
            this.heap[right].score > this.heap[largest].score
        ) {
            largest = right;
        }

        if (largest !== index) {

            this.swap(index, largest);

            this.heapify(largest);
        }
    }

    peek() {

        return this.heap.length
            ? this.heap[0]
            : null;
    }

    clear() {
        this.heap = [];
    }

    getAll() {
        return [...this.heap];
    }

    size() {
        return this.heap.length;
    }
}


/* =========================================================
   7. TRIE
   Scam keyword searching
   ========================================================= */

class TrieNode {

    constructor() {
        this.children = {};
        this.isEnd = false;
    }
}


class ScamTrie {

    constructor() {
        this.root = new TrieNode();
    }

    insert(word) {

        if (!word) {
            return;
        }

        word = word.toLowerCase();

        let current = this.root;

        for (const char of word) {

            if (!current.children[char]) {
                current.children[char] = new TrieNode();
            }

            current = current.children[char];
        }

        current.isEnd = true;
    }

    search(word) {

        if (!word) {
            return false;
        }

        word = word.toLowerCase();

        let current = this.root;

        for (const char of word) {

            if (!current.children[char]) {
                return false;
            }

            current = current.children[char];
        }

        return current.isEnd;
    }

    findKeywords(text) {

        if (!text) {
            return [];
        }

        const words = text
            .toLowerCase()
            .match(/[a-z0-9@._-]+/g) || [];

        const found = [];

        for (const word of words) {

            if (this.search(word)) {
                found.push(word);
            }
        }

        return [...new Set(found)];
    }
}


/* =========================================================
   8. CREATE DSA OBJECTS
   ========================================================= */

const fraudSignals = new RiskSet();

const evidenceStack = new EvidenceStack();

const caseQueue = new CaseQueue();

const caseHistory = new CaseLinkedList();

const fraudHashTable = new FraudHashTable();

const riskHeap = new RiskMaxHeap();

const scamTrie = new ScamTrie();


/* =========================================================
   9. TRIE KEYWORDS
   ========================================================= */

const scamKeywords = [

    "urgent",
    "immediately",
    "verify",
    "verification",
    "kyc",
    "blocked",
    "block",
    "suspend",
    "suspended",
    "account",
    "bank",
    "click",
    "winner",
    "prize",
    "reward",
    "cashback",
    "refund",
    "claim",
    "password",
    "otp",
    "pin",
    "cvv",
    "payment",
    "money",
    "lottery",
    "offer",
    "free",
    "login",
    "secure",
    "update",
    "confirm"
];


scamKeywords.forEach(keyword => {
    scamTrie.insert(keyword);
});


/* =========================================================
   10. GLOBAL NETWORK
   ========================================================= */

let lastFraudNetwork = null;


/* =========================================================
   11. PROCESS DSA RESULT
   ========================================================= */

function processDSAResult(result) {

    if (!result) {
        return;
    }

    /* ---------- SET ---------- */

    fraudSignals.clear();

    if (Array.isArray(result.signals)) {

        result.signals.forEach(signal => {

            if (signal) {
                fraudSignals.add(signal);
            }

        });
    }


    /* ---------- STACK ---------- */

    evidenceStack.clear();

    if (Array.isArray(result.reasons)) {

        result.reasons.forEach(reason => {

            if (reason) {
                evidenceStack.push(reason);
            }

        });
    }


    /* ---------- QUEUE ---------- */

    caseQueue.enqueue({
        id: result.id || generateCaseId(),
        score: Number(result.score) || 0,
        timestamp: new Date().toLocaleTimeString()
    });


    /* ---------- LINKED LIST ---------- */

    caseHistory.add({
        id: result.id || generateCaseId(),
        score: Number(result.score) || 0,
        risk: result.risk || "UNKNOWN"
    });


    /* ---------- HASH TABLE ---------- */

    fraudHashTable.clear();

    if (result.url) {

        fraudHashTable.set(
            "URL",
            result.url
        );
    }

    if (result.upi) {

        fraudHashTable.set(
            "UPI",
            result.upi
        );
    }

    if (result.phone) {

        fraudHashTable.set(
            "PHONE",
            result.phone
        );
    }

    if (result.account) {

        fraudHashTable.set(
            "ACCOUNT",
            result.account
        );
    }


    /* ---------- HEAP ---------- */

    riskHeap.insert({
        id: result.id || generateCaseId(),
        score: Number(result.score) || 0
    });


    /* ---------- UPDATE DSA UI ---------- */

    updateDSADashboard();


    /* ---------- BUILD NETWORK ---------- */

    buildFraudNetwork(result);
}


/* =========================================================
   12. DSA DASHBOARD
   ========================================================= */

function updateDSADashboard() {

    const setElement =
        document.getElementById("dsaSet");

    const stackElement =
        document.getElementById("dsaStack");

    const queueElement =
        document.getElementById("dsaQueue");

    const linkedListElement =
        document.getElementById("dsaLinkedList");

    const hashElement =
        document.getElementById("dsaHash");

    const heapElement =
        document.getElementById("dsaHeap");

    const trieElement =
        document.getElementById("dsaTrie");


    /* SET */

    if (setElement) {

        const values = fraudSignals.getAll();

        setElement.textContent =
            values.length
                ? values.join(", ")
                : "No indicators";
    }


    /* STACK */

    if (stackElement) {

        const values =
            evidenceStack.getAll();

        stackElement.textContent =
            values.length
                ? values.slice(0, 3).join(" | ")
                : "Empty";
    }


    /* QUEUE */

    if (queueElement) {

        queueElement.textContent =
            `${caseQueue.size()} case(s)`;
    }


    /* LINKED LIST */

    if (linkedListElement) {

        linkedListElement.textContent =
            `${caseHistory.size()} case(s)`;
    }


    /* HASH TABLE */

    if (hashElement) {

        hashElement.textContent =
            `${fraudHashTable.size()} entities`;
    }


    /* HEAP */

    if (heapElement) {

        const top =
            riskHeap.peek();

        heapElement.textContent =
            top
                ? `Risk ${top.score}`
                : "Empty";
    }


    /* TRIE */

    if (trieElement) {

        trieElement.textContent =
            `${scamKeywords.length} keywords indexed`;
    }
}


/* =========================================================
   13. FRAUD GRAPH
   ========================================================= */

class FraudGraph {

    constructor() {

        this.graph = new Map();
    }


    addNode(node) {

        if (!node) {
            return;
        }

        if (!this.graph.has(node)) {

            this.graph.set(
                node,
                new Set()
            );
        }
    }


    addEdge(a, b) {

        if (!a || !b) {
            return;
        }

        this.addNode(a);
        this.addNode(b);

        this.graph.get(a).add(b);
        this.graph.get(b).add(a);
    }


    clear() {

        this.graph.clear();
    }


    getAll() {

        return this.graph;
    }


    BFS(start) {

        if (!this.graph.has(start)) {
            return [];
        }

        const visited = new Set();

        const queue = [start];

        const result = [];


        visited.add(start);


        while (queue.length > 0) {

            const node = queue.shift();

            result.push(node);


            const neighbors =
                this.graph.get(node) || [];


            neighbors.forEach(neighbor => {

                if (!visited.has(neighbor)) {

                    visited.add(neighbor);

                    queue.push(neighbor);
                }

            });
        }


        return result;
    }


    DFS(start) {

        if (!this.graph.has(start)) {
            return [];
        }

        const visited = new Set();

        const result = [];


        const visit = (node) => {

            if (visited.has(node)) {
                return;
            }

            visited.add(node);

            result.push(node);


            const neighbors =
                this.graph.get(node) || [];


            neighbors.forEach(neighbor => {

                visit(neighbor);

            });
        };


        visit(start);


        return result;
    }
}


/* =========================================================
   14. GENERATE CASE ID
   ========================================================= */

function generateCaseId() {

    return (
        "CASE-" +
        Math.random()
            .toString(36)
            .substring(2, 8)
            .toUpperCase()
    );
}


/* =========================================================
   15. EXTRACT URL FROM TEXT
   ========================================================= */

function extractURL(text) {

    if (!text) {
        return null;
    }

    const match =
        text.match(
            /(https?:\/\/[^\s]+)/i
        );

    return match
        ? match[1]
        : null;
}


/* =========================================================
   16. EXTRACT UPI FROM TEXT
   ========================================================= */

function extractUPI(text) {

    if (!text) {
        return null;
    }

    const match =
        text.match(
            /[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+/i
        );

    return match
        ? match[0]
        : null;
}


/* =========================================================
   17. EXTRACT PHONE NUMBER
   ========================================================= */

function extractPhone(text) {

    if (!text) {
        return null;
    }

    const match =
        text.match(
            /(?:\+91[\s-]?)?[6-9]\d{9}/
        );

    return match
        ? match[0]
        : null;
}


/* =========================================================
   18. BUILD DYNAMIC FRAUD NETWORK
   ========================================================= */

function buildFraudNetwork(result) {

    const network =
        new FraudGraph();


    /* -----------------------------------------
       CASE NODE
       ----------------------------------------- */

    const caseId =
        result.id || generateCaseId();

    const caseNode =
        caseId;


    network.addNode(caseNode);


    /* -----------------------------------------
       RESULT TEXT
       ----------------------------------------- */

    const text =
        [
            result.text,
            result.message,
            result.content,
            result.url,
            result.upi
        ]
        .filter(Boolean)
        .join(" ");


    /* -----------------------------------------
       URL NODE
       ----------------------------------------- */

    let detectedURL =
        result.url ||
        extractURL(text);


    if (detectedURL) {

        const urlNode =
            "URL: " + detectedURL;

        network.addEdge(
            caseNode,
            urlNode
        );


        const domain =
            getDomain(detectedURL);


        if (domain) {

            const domainNode =
                "DOMAIN: " + domain;

            network.addEdge(
                urlNode,
                domainNode
            );
        }
    }


    /* -----------------------------------------
       UPI NODE
       ----------------------------------------- */

    let detectedUPI =
        result.upi ||
        extractUPI(text);


    if (detectedUPI) {

        const upiNode =
            "UPI: " + detectedUPI;

        network.addEdge(
            caseNode,
            upiNode
        );


        network.addEdge(
            upiNode,
            "PAYMENT"
        );
    }


    /* -----------------------------------------
       PHONE NODE
       ----------------------------------------- */

    let detectedPhone =
        result.phone ||
        extractPhone(text);


    if (detectedPhone) {

        const phoneNode =
            "PHONE: " + detectedPhone;

        network.addEdge(
            caseNode,
            phoneNode
        );


        network.addEdge(
            phoneNode,
            "SENDER"
        );
    }


    /* -----------------------------------------
       SCAM KEYWORDS
       ----------------------------------------- */

    const detectedKeywords =
        scamTrie.findKeywords(text);


    detectedKeywords
        .slice(0, 8)
        .forEach(keyword => {

            const keywordNode =
                "KEYWORD: " +
                keyword.toUpperCase();

            network.addEdge(
                caseNode,
                keywordNode
            );
        });


    /* -----------------------------------------
       SIGNALS
       ----------------------------------------- */

    if (Array.isArray(result.signals)) {

        result.signals
            .slice(0, 8)
            .forEach(signal => {

                if (!signal) {
                    return;
                }

                const signalNode =
                    "SIGNAL: " +
                    String(signal).toUpperCase();

                network.addEdge(
                    caseNode,
                    signalNode
                );
            });
    }


    /* -----------------------------------------
       RISK LEVEL
       ----------------------------------------- */

    if (result.risk) {

        const riskNode =
            "RISK: " +
            String(result.risk).toUpperCase();

        network.addEdge(
            caseNode,
            riskNode
        );
    }


    /* -----------------------------------------
       FALLBACK
       ----------------------------------------- */

    if (network.graph.size === 1) {

        network.addEdge(
            caseNode,
            "ANALYSIS"
        );

        network.addEdge(
            "ANALYSIS",
            "RISK ENGINE"
        );
    }


    /* -----------------------------------------
       SAVE NETWORK
       ----------------------------------------- */

    lastFraudNetwork = network;


    /* -----------------------------------------
       BFS / DFS
       ----------------------------------------- */

    const bfs =
        network.BFS(caseNode);

    const dfs =
        network.DFS(caseNode);


    /* -----------------------------------------
       RENDER
       ----------------------------------------- */

    renderFraudNetworkUI(
        network,
        bfs,
        dfs
    );
}


/* =========================================================
   19. GET DOMAIN
   ========================================================= */

function getDomain(url) {

    try {

        const parsed =
            new URL(url);

        return parsed.hostname;

    } catch (error) {

        return null;
    }
}


/* =========================================================
   20. NODE TYPE
   ========================================================= */

function getNodeType(node) {

    const value =
        String(node).toUpperCase();


    if (value.startsWith("CASE-")) {
        return "case";
    }

    if (value.startsWith("URL:")) {
        return "url";
    }

    if (value.startsWith("DOMAIN:")) {
        return "domain";
    }

    if (value.startsWith("UPI:")) {
        return "upi";
    }

    if (value.startsWith("PHONE:")) {
        return "phone";
    }

    if (value.startsWith("KEYWORD:")) {
        return "keyword";
    }

    if (value.startsWith("SIGNAL:")) {
        return "signal";
    }

    if (value.startsWith("RISK:")) {
        return "risk";
    }

    if (value === "PAYMENT") {
        return "payment";
    }

    if (value === "SENDER") {
        return "sender";
    }

    return "generic";
}


/* =========================================================
   21. SHORTEN NODE LABEL
   ========================================================= */

function shortenNodeLabel(node) {

    const text =
        String(node);


    if (text.length <= 25) {
        return text;
    }


    return (
        text.substring(0, 22) +
        "..."
    );
}


/* =========================================================
   22. RENDER NETWORK UI
   ========================================================= */

function renderFraudNetworkUI(
    network,
    bfs,
    dfs
) {

    const canvas =
        document.getElementById(
            "fraudNetworkCanvas"
        );


    if (!canvas) {
        return;
    }


    /* -----------------------------------------
       CLEAR OLD NETWORK
       ----------------------------------------- */

    canvas.innerHTML = "";


    /* -----------------------------------------
       GET NODES
       IMPORTANT:
       graph is a MAP
       ----------------------------------------- */

    const nodes =
        Array.from(
            network.graph.keys()
        );


    /* -----------------------------------------
       GET EDGES
       ----------------------------------------- */

    const edges = [];

    const edgeSet =
        new Set();


    network.graph.forEach(
        (neighbors, node) => {

            neighbors.forEach(
                neighbor => {

                    const key =
                        [node, neighbor]
                            .sort()
                            .join("|||");


                    if (!edgeSet.has(key)) {

                        edgeSet.add(key);

                        edges.push({
                            from: node,
                            to: neighbor
                        });
                    }
                }
            );
        }
    );


    /* -----------------------------------------
       NETWORK CONTAINER
       ----------------------------------------- */

    const wrapper =
        document.createElement("div");


    wrapper.className =
        "network-visual";


    wrapper.style.position =
        "relative";

    wrapper.style.width =
        "100%";

    wrapper.style.height =
        "430px";

    wrapper.style.overflow =
        "hidden";


    /* -----------------------------------------
       SVG
       ----------------------------------------- */

    const svg =
        document.createElementNS(
            "http://www.w3.org/2000/svg",
            "svg"
        );


    svg.setAttribute(
        "viewBox",
        "0 0 100 100"
    );


    svg.style.position =
        "absolute";

    svg.style.inset =
        "0";

    svg.style.width =
        "100%";

    svg.style.height =
        "100%";


    /* -----------------------------------------
       NODE POSITIONS
       ----------------------------------------- */

    const positions = {};


    const total =
        Math.max(nodes.length, 1);


    nodes.forEach(
        (node, index) => {

            const type =
                getNodeType(node);


            let x;
            let y;


            /* CASE CENTER */

            if (type === "case") {

                x = 50;
                y = 50;

            }

            /* URL */

            else if (type === "url") {

                x = 78;
                y = 22;

            }

            /* DOMAIN */

            else if (type === "domain") {

                x = 92;
                y = 48;

            }

            /* UPI */

            else if (type === "upi") {

                x = 20;
                y = 25;

            }

            /* PHONE */

            else if (type === "phone") {

                x = 20;
                y = 75;

            }

            /* KEYWORD */

            else if (type === "keyword") {

                const keywordIndex =
                    index % 8;

                x =
                    35 +
                    (keywordIndex % 4) * 12;

                y =
                    10 +
                    Math.floor(
                        keywordIndex / 4
                    ) * 80;

            }

            /* SIGNAL */

            else if (type === "signal") {

                x =
                    55 +
                    (index % 3) * 15;

                y =
                    15 +
                    (index % 4) * 20;

            }

            /* RISK */

            else if (type === "risk") {

                x = 80;
                y = 78;

            }

            /* GENERIC */

            else {

                const angle =
                    (index / total) *
                    Math.PI *
                    2;

                const radius = 32;

                x =
                    50 +
                    Math.cos(angle) *
                    radius;

                y =
                    50 +
                    Math.sin(angle) *
                    radius;
            }


            positions[node] = {
                x,
                y
            };
        }
    );


    /* -----------------------------------------
       DRAW EDGES
       ----------------------------------------- */

    edges.forEach(edge => {

        const from =
            positions[edge.from];

        const to =
            positions[edge.to];


        if (!from || !to) {
            return;
        }


        const line =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "line"
            );


        line.setAttribute(
            "x1",
            from.x
        );

        line.setAttribute(
            "y1",
            from.y
        );

        line.setAttribute(
            "x2",
            to.x
        );

        line.setAttribute(
            "y2",
            to.y
        );


        line.setAttribute(
            "class",
            "network-line"
        );


        svg.appendChild(line);
    });


    wrapper.appendChild(svg);


    /* -----------------------------------------
       DRAW NODES
       ----------------------------------------- */

    nodes.forEach(node => {

        const position =
            positions[node];


        const type =
            getNodeType(node);


        const nodeElement =
            document.createElement("div");


        nodeElement.className =
            "network-node " +
            type;


        nodeElement.textContent =
            shortenNodeLabel(node);


        nodeElement.title =
            node;


        nodeElement.style.position =
            "absolute";


        nodeElement.style.left =
            position.x + "%";


        nodeElement.style.top =
            position.y + "%";


        nodeElement.style.transform =
            "translate(-50%, -50%)";


        wrapper.appendChild(
            nodeElement
        );
    });


    /* -----------------------------------------
       ADD TO CANVAS
       ----------------------------------------- */

    canvas.appendChild(
        wrapper
    );


    /* -----------------------------------------
       NETWORK STATUS
       ----------------------------------------- */

    const status =
        document.getElementById(
            "networkStatus"
        );


    if (status) {

        status.textContent =
            "Dynamic network generated from current analysis";
    }


    /* -----------------------------------------
       BFS
       ----------------------------------------- */

    const bfsElement =
        document.getElementById(
            "networkBFS"
        );


    if (bfsElement) {

        bfsElement.textContent =
            bfs.length
                ? bfs.join(" → ")
                : "No traversal";
    }


    /* -----------------------------------------
       DFS
       ----------------------------------------- */

    const dfsElement =
        document.getElementById(
            "networkDFS"
        );


    if (dfsElement) {

        dfsElement.textContent =
            dfs.length
                ? dfs.join(" → ")
                : "No traversal";
    }


    /* -----------------------------------------
       NODE COUNT
       ----------------------------------------- */

    const nodeCount =
        document.getElementById(
            "networkNodes"
        );


    if (nodeCount) {

        nodeCount.textContent =
            `${nodes.length} nodes`;
    }


    /* -----------------------------------------
       EDGE COUNT
       ----------------------------------------- */

    const edgeCount =
        document.getElementById(
            "networkEdges"
        );


    if (edgeCount) {

        edgeCount.textContent =
            `${edges.length} connections`;
    }
}


/* =========================================================
   23. KEEP ORIGINAL PROCESS FUNCTION SAFE
   ========================================================= */

window.processDSAResult =
    processDSAResult;


/* =========================================================
   24. GLOBAL DSA OBJECTS
   ========================================================= */

window.fraudSignals =
    fraudSignals;

window.evidenceStack =
    evidenceStack;

window.caseQueue =
    caseQueue;

window.caseHistory =
    caseHistory;

window.fraudHashTable =
    fraudHashTable;

window.riskHeap =
    riskHeap;

window.scamTrie =
    scamTrie;

window.lastFraudNetwork =
    lastFraudNetwork;


/* =========================================================
   25. DOM READY
   ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        updateDSADashboard();

        console.log(
            "FraudShield DSA Engine loaded successfully."
        );

        console.log(
            "DSA Structures:",
            {
                Set: fraudSignals,
                Stack: evidenceStack,
                Queue: caseQueue,
                LinkedList: caseHistory,
                HashTable: fraudHashTable,
                MaxHeap: riskHeap,
                Trie: scamTrie
            }
        );
    }
);


/* =========================================================
   26. DEBUG HELPER
   ========================================================= */

window.showDSAData =
    function () {

        console.log(
            "===== FRAUDSHIELD DSA DATA ====="
        );

        console.log(
            "SET:",
            fraudSignals.getAll()
        );

        console.log(
            "STACK:",
            evidenceStack.getAll()
        );

        console.log(
            "QUEUE:",
            caseQueue.getAll()
        );

        console.log(
            "LINKED LIST:",
            caseHistory.getAll()
        );

        console.log(
            "HASH TABLE:",
            fraudHashTable.getAll()
        );

        console.log(
            "MAX HEAP:",
            riskHeap.getAll()
        );

        console.log(
            "TRIE KEYWORDS:",
            scamKeywords
        );

        console.log(
            "NETWORK:",
            lastFraudNetwork
        );
    };


/* =========================================================
   END OF FRAUDSHIELD DSA ENGINE
   ========================================================= */