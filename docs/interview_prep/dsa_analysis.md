# Data Structures & Algorithms Analysis

This document explains the specific Data Structures and Algorithms (DSA) used within NullProtocol's codebase.

## 1. Breadth-First Search (BFS)
**Used in**: `recon/ReconEnhancerTools/crawler.py`

- **Purpose**: To crawl a website level-by-level (visiting all links on the home page before moving deeper) to find forms and parameters.
- **Implementation**:
    - We use a `collections.deque` (Double Ended Queue) as a FIFO (First-In-First-Out) queue.
    - **Logic**:
        1.  Add `start_url` to `queue`.
        2.  While `queue` is not empty:
        3.  Pop URL from left (`popleft()`).
        4.  Fetch page.
        5.  Extract new links and add to right of `queue`.
- **Why BFS?**: BFS is better than DFS (Depth-First Search) for web crawling because it ensures we scan the most critical "top-level" pages first, rather than getting lost down a deep rabbit hole of 1000 sub-links on a minor page.

## 2. Hash Sets (Deduplication)
**Used in**: `recon/Domain.py`, `crawler.py`, `main.py`

- **Purpose**: To ensure we don't scan the same IP, Subdomain, or URL twice.
- **Implementation**: Python's `set()` data structure.
- **Time Complexity**: Insertions and Lookups are **O(1)** (average case).
- **Code Reference**:
    ```python
    self.visited = set()
    if link not in self.visited:
        self.visited.add(link)
    ```
- **Why Sets?**: Using a List `[]` for checking `if x in list` would be **O(N)**. With thousands of subdomains, a Set is significantly faster.

## 3. Hash Maps (Dictionaries)
**Used in**: Everywhere (`enhanced.json`, `exploit_searcher.py`)

- **Purpose**: storing structured data where we need fast access by a key.
- **Implementation**: Python's `dict()`.
- **Usage**:
    - **Vulnerability Mapping**: `self.attack_patterns` maps a vulnerability type ("xss") to a list of regex patterns.
    - **Results Storage**: The entire reporting structure is a nested dictionary (JSON).

## 4. Regular Expressions (String Matching)
**Used in**: `recon/ReconEnhancerTools/exploit_searcher.py`, `IpExtraction.py`

- **Purpose**: Pattern matching for text processing.
- **Implementation**:
    - **IP Validation**: Verifying if a string matches the format `Num.Num.Num.Num`.
    - **Vulnerability Detection**: Checking if an exploit title contains keywords like "Remote Code Execution" or "SQLi".
- **Algorithm**: Regex engines use Finite Automata (DFA/NFA) to process state transitions for identifying patterns.

## 5. Concurrency (Threading)
**Used in**: `brute/attack_chain.py`

- **Purpose**: Running multiple tasks simultaneously (though we typically run external tools sequentially, Hydra itself uses internal threading).
- **Concept**: Our Python script invokes external tools (Hydra, Masscan) that implement multi-threading.
    - **Masscan**: Uses asynchronous transmission (separate transmit/receive threads) to achieve high packet rates.
    - **Hydra**: Uses a thread pool to try multiple passwords at once against a service.
