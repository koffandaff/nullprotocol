# Requirements Analysis

This document analyzes the python dependencies in `requirements.txt` and explains why each is necessary for NullProtocol.

## Core Libraries

### `requests >= 2.31.0`
- **Purpose**: Making HTTP requests.
- **Use Cases**: 
    - Fetching HTML for the `WebScanner`.
    - Crawling pages in `crawler.py`.
    - Querying the Ollama API in `ollama_handler.py`.
    - Interacting with APIs.
- **Criticality**: **High**. The recon module relies heavily on this.

### `xmltodict >= 0.13.0`
- **Purpose**: Converting XML data to Python Dictionaries.
- **Use Cases**:
    - Parsing **Nmap** output (`-oX` format). Nmap produces XML, which is hard to work with in Python. This library makes it accessible as a standard JSON-like dictionary.
- **Criticality**: **High**. Essential for the Nmap pipeline.

### `python-magic >= 0.4.27`
- **Purpose**: File type identification (libmagic binding).
- **Use Cases**:
    - Determining if a downloaded file is a text file, binary, image, etc., regardless of extension.
    - Used during `ReconEnhancer` to categorize discovered assets.
- **Criticality**: Medium.

## User Interface

### `rich == 13.7.1`
- **Purpose**: Terminal formatting library.
- **Use Cases**:
    - **Colored Output**: `[green]Success[/green]`, `[red]Error[/red]`.
    - **Tables**: The `make_table` utility function uses Rich to draw ASCII tables for scan results.
    - **Progress Bars**: The spinners and progress bars during invalid scans are powered by Rich.
- **Criticality**: **High**. This defines the "User Experience" of the CLI.

## Web Reporting (HostRecon)

### `flask >= 3.0.0`
- **Purpose**: Lightweight Web Framework.
- **Use Cases**:
    - Hosting the `hostrecon.py` dashboard.
    - Serving HTML templates and static assets (CSS/JS).
    - Handling routes like `/report/<domain>`.
- **Criticality**: **High** (for the Dashboard feature).

### `jinja2 >= 3.1.0`
- **Purpose**: Templating Engine.
- **Use Cases**:
    - Rendering `index.html` and `scan_detail.html` with dynamic data from `enhanced.json`.
    - It's a dependency of Flask but also used explicitly for generating static HTML reports.

## Analysis & AI

### `beautifulsoup4 >= 4.12.0`
- **Purpose**: HTML Parsing.
- **Use Cases**:
    - Parsing HTML responses in `crawler.py` to find `<a href>` links and `<form>` tags.
    - Extracting page titles and meta headers in `web_scanner.py`.
- **Criticality**: **High** (for Web Analysis).

### `ollama >= 0.1.0`
- **Purpose**: Python client for Ollama API.
- **Use Cases**:
    - Sending prompts to the local LLM (e.g., Llama3) to analyze JSON scan data and generate summaries.
- **Criticality**: Low (Optional AI feature).
