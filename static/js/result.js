function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeHTML(value) {
    return escapeHtml(value);
}

document.addEventListener("DOMContentLoaded", () => {
    loadAnalysisResult();
});

async function loadAnalysisResult() {
    const container = document.getElementById("result-content");

    try {
        const response = await fetch(`/api/history/${ANALYSIS_ID}`);

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const result = await response.json();

        if (!result.success || !result.data) {
            throw new Error(result.error || "Unable to load analysis");
        }

        renderResult(result.data);

    } catch (error) {
        console.error("Result loading error:", error);

        container.innerHTML = `
            <div class="alert alert-danger">
                <strong>Unable to load analysis results.</strong>
                <p>${escapeHTML(error.message)}</p>
            </div>
        `;
    }
}


/* =========================================================
   MAIN RESULT RENDERER
   ========================================================= */

function renderResult(analysis) {
    const container = document.getElementById("result-content");

    const analysisData = analysis.analysis_data || {};
    const risk = analysisData.risk || {};
    const verdict = analysisData.verdict || {};

    let indicators = analysis.indicators || [];

    if (!Array.isArray(indicators)) {
        indicators = indicators.detected_indicators || [];
    }

    const metadata = analysisData.metadata || {};
    const stringsData = analysisData.strings || {};
    const entropyData = analysisData.entropy || {};
    const peData = analysisData.pe_analysis || {};

    const riskScore =
        analysis.risk_score ??
        risk.score ??
        0;

    const riskLevel =
        analysis.severity ||
        risk.risk_level ||
        "UNKNOWN";

    const verdictText =
        verdict.verdict ||
        getVerdictText(riskLevel);

    const recommendation =
        verdict.recommendation ||
        "Review the analysis results before trusting this file.";

    const indicatorCount = indicators.length;

    container.innerHTML = `
        <!-- INVESTIGATION SUMMARY -->
        <section class="investigation-summary">

            <div class="investigation-summary-main">

                <div class="investigation-file">

                    <div class="result-eyebrow">
                        INVESTIGATION #${escapeHTML(analysis.id)}
                    </div>

                    <h2>
                        ${escapeHTML(analysis.filename || "Unnamed file")}
                    </h2>

                    <div class="investigation-meta">

                        <span>
                            ${escapeHTML(analysis.file_type || "Unknown")}
                        </span>

                        <span class="meta-separator">•</span>

                        <span>
                            ${escapeHTML(analysis.mime_type || "Unknown")}
                        </span>

                        <span class="meta-separator">•</span>

                        <span>
                            ${formatFileSize(analysis.file_size)}
                        </span>

                    </div>

                </div>

                <div class="investigation-risk risk-${String(riskLevel).toLowerCase()}">

                    <div class="risk-score-block">

                        <span class="risk-score-caption">
                            RISK SCORE
                        </span>

                        <strong class="risk-score-number">
                            ${escapeHTML(riskScore)}
                        </strong>

                        <span class="risk-score-scale">
                            / 100
                        </span>

                    </div>

                    <div class="risk-level">
                        ${escapeHTML(riskLevel)}
                    </div>

                </div>

            </div>

            <div class="investigation-verdict">

                <div>

                    <div class="verdict-label">
                        ANALYST VERDICT
                    </div>

                    <h3>
                        ${escapeHTML(verdictText)}
                    </h3>

                </div>

                <p>
                    ${escapeHTML(recommendation)}
                </p>

            </div>

        </section>


        <!-- FILE IDENTITY -->
        <section class="result-section">

            <div class="section-heading">

                <div>

                    <div class="result-eyebrow">
                        FILE IDENTIFICATION
                    </div>

                    <h2>File identity</h2>

                </div>

            </div>

            <div class="result-info-grid">

                <div class="result-info-item">

                    <span class="result-info-label">
                        Filename
                    </span>

                    <strong>
                        ${escapeHTML(analysis.filename || "N/A")}
                    </strong>

                </div>


                <div class="result-info-item">

                    <span class="result-info-label">
                        File type
                    </span>

                    <strong>
                        ${escapeHTML(analysis.file_type || "Unknown")}
                    </strong>

                </div>


                <div class="result-info-item">

                    <span class="result-info-label">
                        MIME type
                    </span>

                    <strong class="technical-value">
                        ${escapeHTML(analysis.mime_type || "Unknown")}
                    </strong>

                </div>


                <div class="result-info-item">

                    <span class="result-info-label">
                        File size
                    </span>

                    <strong>
                        ${formatFileSize(analysis.file_size)}
                    </strong>

                </div>


                <div class="result-info-item">

                    <span class="result-info-label">
                        Entropy
                    </span>

                    <strong>
                        ${
                            analysis.entropy !== null &&
                            analysis.entropy !== undefined
                                ? escapeHTML(analysis.entropy)
                                : "N/A"
                        }
                    </strong>

                </div>


                <div class="result-info-item">

                    <span class="result-info-label">
                        Analysis ID
                    </span>

                    <strong class="technical-value">
                        #${escapeHTML(analysis.id)}
                    </strong>

                </div>

            </div>

        </section>


        <!-- HASHES -->
        <section class="result-section">

            <div class="section-heading">

                <div>

                    <div class="result-eyebrow">
                        FILE FINGERPRINT
                    </div>

                    <h2>Cryptographic hashes</h2>

                </div>

            </div>

            <div class="hash-list">

                <div class="hash-item">

                    <div class="hash-label">
                        MD5
                    </div>

                    <code class="hash-value">
                        ${escapeHTML(analysis.md5 || "N/A")}
                    </code>

                </div>


                <div class="hash-item">

                    <div class="hash-label">
                        SHA-1
                    </div>

                    <code class="hash-value">
                        ${escapeHTML(analysis.sha1 || "N/A")}
                    </code>

                </div>


                <div class="hash-item hash-primary">

                    <div class="hash-label">
                        SHA-256
                    </div>

                    <code class="hash-value">
                        ${escapeHTML(analysis.sha256 || "N/A")}
                    </code>

                </div>

            </div>

        </section>


        <!-- INDICATORS -->
        <section class="result-section">

            <div class="section-heading section-heading-with-count">

                <div>

                    <div class="result-eyebrow">
                        THREAT FINDINGS
                    </div>

                    <h2>
                        Detected indicators
                    </h2>

                </div>

                <span class="section-count">
                    ${indicatorCount} detected
                </span>

            </div>


            <div class="indicators-list">

                ${
                    indicatorCount
                        ? indicators.map(renderIndicator).join("")
                        : `
                            <div class="result-empty">

                                <strong>
                                    No suspicious indicators detected
                                </strong>

                                <span>
                                    No indicators contributed to the current risk assessment.
                                </span>

                            </div>
                        `
                }

            </div>

        </section>


        <!-- SCORE BREAKDOWN -->
        <!-- SCORE BREAKDOWN -->
<section class="result-section">

    <div class="section-heading-row">

        <div>
            <div class="result-eyebrow">
                RISK ENGINE
            </div>

            <h2>
                Score breakdown
            </h2>
        </div>

        <div class="score-total">
            ${escapeHTML(riskScore)} / 100
        </div>

    </div>


    <div class="score-breakdown-panel">

        <div class="score-table-header">

            <span>
                INDICATOR
            </span>

            <span>
                ID
            </span>

            <span>
                CONTRIBUTION
            </span>

        </div>


        <div class="score-table-body">

            ${
                Array.isArray(indicators) &&
                indicators.length

                    ? indicators.map(indicator => {

                        const name =
                            indicator.name ||
                            indicator.id ||
                            "Indicator";

                        const id =
                            indicator.id ||
                            "UNKNOWN";

                        const score =
                            Number(
                                indicator.score
                            ) || 0;

                        return `
                            <div class="score-table-row">

                                <div class="score-indicator-name">
                                    ${escapeHTML(name)}
                                </div>

                                <code class="score-indicator-id">
                                    ${escapeHTML(id)}
                                </code>

                                <strong class="score-contribution">
                                    +${score}
                                </strong>

                            </div>
                        `;

                    }).join("")

                    : `
                        <div class="score-table-empty">
                            No indicators contributed to the risk score.
                        </div>
                    `
            }

        </div>


        <div class="score-table-footer">

            <span>
                TOTAL RISK SCORE
            </span>

            <strong>
                ${escapeHTML(riskScore)} / 100
            </strong>

        </div>

    </div>

</section>


        <!-- METADATA -->
        <section class="result-section">

            <div class="section-heading">

                <div>

                    <div class="result-eyebrow">
                        FILE CONTEXT
                    </div>

                    <h2>
                        Metadata
                    </h2>

                </div>

            </div>

            <div class="metadata-grid">
    ${renderMetadata(metadata, analysis)}
</div>

        </section>


        <!-- STRINGS -->
        <section class="result-section">

            <div class="section-heading">

                <div>

                    <div class="result-eyebrow">
                        CONTENT EXTRACTION
                    </div>

                    <h2>
                        Extracted strings
                    </h2>

                </div>

            </div>

            <div class="strings-list">
                ${renderStrings(stringsData)}
            </div>

        </section>

<!-- ENTROPY -->
<section class="result-section">

    <div class="section-heading">

        <div>
            <div class="result-eyebrow">
                STATISTICAL ANALYSIS
            </div>

            <h2>
                Entropy analysis
            </h2>
        </div>

    </div>


    <div class="entropy-panel">

        <div class="entropy-summary">

            <div class="entropy-score">

                <strong>
                    ${escapeHTML(
                        entropyData.entropy ??
                        analysis.entropy ??
                        "N/A"
                    )}
                </strong>

                <span>
                    / 8.00
                </span>

            </div>

            <div class="entropy-caption">
                SHANNON ENTROPY
            </div>

        </div>


        <div class="entropy-analysis">

            <div class="entropy-status">

                <span class="entropy-status-badge">
                    ${escapeHTML(
                        entropyData.category ||
                        "UNAVAILABLE"
                    )}
                </span>

            </div>


            <div class="entropy-scale">

                <div class="entropy-scale-track">

                    <div
                        class="entropy-scale-fill"
                        style="width:${Math.min(
                            100,
                            (
                                Number(
                                    entropyData.entropy ??
                                    analysis.entropy ??
                                    0
                                ) / 8
                            ) * 100
                        )}%"
                    ></div>

                    <div
                        class="entropy-scale-marker"
                        style="left:${Math.min(
                            100,
                            (
                                Number(
                                    entropyData.entropy ??
                                    analysis.entropy ??
                                    0
                                ) / 8
                            ) * 100
                        )}%"
                    ></div>

                </div>


                <div class="entropy-scale-labels">

                    <span>0</span>
                    <span>2</span>
                    <span>4</span>
                    <span>6</span>
                    <span>8</span>

                </div>


                <div class="entropy-scale-zones">

                    <span>LOW</span>
                    <span>NORMAL</span>
                    <span>MODERATE</span>
                    <span>HIGH</span>

                </div>

            </div>

        </div>


        <div class="entropy-explanation">

            <span class="entropy-explanation-label">
                INTERPRETATION
            </span>

            <p>
                ${escapeHTML(
                    entropyData.explanation ||
                    "Entropy describes the distribution of byte values in the file."
                )}
            </p>

        </div>

    </div>

</section>


        <!-- PE ANALYSIS -->
        <section class="result-section">

            <div class="section-heading">

                <div>

                    <div class="result-eyebrow">
                        EXECUTABLE ANALYSIS
                    </div>

                    <h2>
                        PE analysis
                    </h2>

                </div>

            </div>


            <div class="pe-grid">

                <div class="metadata-item">

                    <div class="metadata-key">
                        PE FORMAT
                    </div>

                    <div class="pe-status ${
                        peData.is_pe
                            ? "pe-detected"
                            : "pe-not-detected"
                    }">

                        ${
                            peData.is_pe
                                ? "PE DETECTED"
                                : "NOT A PE FILE"
                        }

                    </div>

                </div>


                <div class="metadata-item">

                    <div class="metadata-key">
                        TECHNICAL RESULT
                    </div>

                    <div class="metadata-value">

                        ${escapeHTML(
                            peData.note ||
                            (
                                peData.is_pe
                                    ? "Windows PE executable detected."
                                    : "File is not a valid Windows PE executable or DLL."
                            )
                        )}

                    </div>

                </div>

            </div>

        </section>


        <!-- SAFETY NOTICE -->
        <div class="static-analysis-notice">

            <div class="notice-mark">
                ✓
            </div>

            <div>

                <strong>
                    STATIC ANALYSIS ONLY
                </strong>

                <span>
                    Uploaded files are never executed by CyberLens.
                    Results are generated through static examination techniques.
                </span>

            </div>

        </div>
    `;
}


/* =========================================================
   INDICATORS
   ========================================================= */

function renderIndicator(indicator) {

    const severity =
        indicator.severity || "UNKNOWN";

    const severityClass =
        String(severity).toLowerCase();

    return `
        <article class="indicator-card">

            <div class="indicator-top">

                <div class="indicator-heading">

                    <div class="indicator-name">
                        ${escapeHTML(
                            indicator.name ||
                            "Unknown Indicator"
                        )}
                    </div>

                    <div class="indicator-id">
                        ${escapeHTML(
                            indicator.id ||
                            "UNKNOWN"
                        )}
                    </div>

                </div>


                <div class="indicator-status">

                    <span class="severity-badge severity-${severityClass}">
                        ${escapeHTML(severity)}
                    </span>

                    <strong class="indicator-score">
                        +${escapeHTML(indicator.score || 0)}
                    </strong>

                </div>

            </div>


            <div class="indicator-evidence">

                <span class="evidence-label">
                    EVIDENCE
                </span>

                <p>
                    ${escapeHTML(
                        indicator.evidence ||
                        "No evidence available."
                    )}
                </p>

            </div>

        </article>
    `;
}


/* =========================================================
   SCORE BREAKDOWN
   ========================================================= */

function renderScoreBreakdown(indicators) {

    if (
        !Array.isArray(indicators) ||
        indicators.length === 0
    ) {
        return `
            <div class="score-empty">
                <strong>No risk contributions detected</strong>
                <span>
                    No indicators contributed to the current risk assessment.
                </span>
            </div>
        `;
    }

    const totalContribution = indicators.reduce(
        (total, indicator) => {
            return total + (
                Number(indicator.score) || 0
            );
        },
        0
    );

    return `
        <div class="score-contribution-list">

            ${indicators.map(indicator => {

                const name =
                    indicator.name ||
                    indicator.id ||
                    "Indicator";

                const id =
                    indicator.id ||
                    "UNKNOWN";

                const score =
                    Number(indicator.score) || 0;

                const evidence =
                    indicator.evidence ||
                    "This indicator contributed to the risk assessment.";

                return `
                    <div class="score-contribution-item">

                        <div class="score-contribution-header">

                            <div class="score-contribution-title">

                                <div class="score-name">
                                    ${escapeHTML(name)}
                                </div>

                                <div class="score-id">
                                    ${escapeHTML(id)}
                                </div>

                            </div>

                            <div class="score-contribution-value">
                                +${score}
                            </div>

                        </div>


                        <div class="score-contribution-evidence">

                            <span>
                                EVIDENCE
                            </span>

                            <p>
                                ${escapeHTML(evidence)}
                            </p>

                        </div>

                    </div>
                `;

            }).join("")}

        </div>


        <div class="score-contribution-total">

            <span>
                TOTAL RISK CONTRIBUTION
            </span>

            <strong>
                +${totalContribution}
            </strong>

        </div>
    `;
}


/* =========================================================
   METADATA
   ========================================================= */

function renderMetadata(metadata, analysis) {

    if (
        !metadata ||
        typeof metadata !== "object"
    ) {
        return `
            <div class="metadata-empty">
                <strong>No metadata available</strong>
                <span>No readable file metadata was found.</span>
            </div>
        `;
    }

    const filesystem =
        metadata.filesystem || {};

    const exif =
        metadata.exif || {};

    const formatSpecific =
        metadata.format_specific ||
        metadata.formatSpecific ||
        {};

    const identification =
        analysis?.analysis_data?.identification ||
        {};


    /* ---------------------------------------------------------
       CLEAN METADATA VALUES
       --------------------------------------------------------- */

    const cleanMetadataText = (value) => {

        if (
            value === null ||
            value === undefined
        ) {
            return null;
        }

        return String(value)
            .replace(
                /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,
                " "
            )
            .replace(/\s+/g, " ")
            .trim();
    };


    const formatValue = (value) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return null;
        }

        if (Array.isArray(value)) {

            const values = value
                .map(item =>
                    cleanMetadataText(item)
                )
                .filter(Boolean);

            return values.length
                ? values.join(" × ")
                : null;
        }

        if (typeof value === "object") {
            return null;
        }

        return cleanMetadataText(value);
    };


    /* ---------------------------------------------------------
       DATE
       --------------------------------------------------------- */

    const formatDate = (value) => {

        if (!value) {
            return null;
        }

        const date =
            new Date(value);

        if (
            !Number.isNaN(
                date.getTime()
            )
        ) {

            return (
                date.toLocaleDateString(
                    "en-GB",
                    {
                        day: "2-digit",
                        month: "short",
                        year: "numeric"
                    }
                )
                +
                " · "
                +
                date.toLocaleTimeString(
                    "en-US",
                    {
                        hour: "numeric",
                        minute: "2-digit"
                    }
                )
            );
        }

        return cleanMetadataText(value);
    };


    /* ---------------------------------------------------------
       FILE SIZE
       --------------------------------------------------------- */

    const formatSize = (bytes) => {

        if (
            bytes === null ||
            bytes === undefined ||
            bytes === ""
        ) {
            return null;
        }

        const size =
            Number(bytes);

        if (Number.isNaN(size)) {
            return cleanMetadataText(bytes);
        }

        if (size < 1024) {
            return `${size} B`;
        }

        if (size < 1024 * 1024) {
            return `${(
                size / 1024
            ).toFixed(2)} KB`;
        }

        return `${(
            size / (1024 * 1024)
        ).toFixed(2)} MB`;
    };


    /* ---------------------------------------------------------
       DIMENSIONS
       --------------------------------------------------------- */

    const getDimensions = () => {

        const width =
            formatSpecific.width ??
            exif.ExifImageWidth ??
            exif.ImageWidth;

        const height =
            formatSpecific.height ??
            exif.ExifImageHeight ??
            exif.ImageHeight;

        if (width && height) {
            return `${width} × ${height}`;
        }

        if (
            Array.isArray(
                formatSpecific.size
            )
        ) {
            return formatSpecific.size.join(" × ");
        }

        if (
            Array.isArray(exif.size)
        ) {
            return exif.size.join(" × ");
        }

        return null;
    };


    /* ---------------------------------------------------------
       EXTENSION / MIME MATCH
       --------------------------------------------------------- */

    const extension =
        identification.extension ||
        analysis?.file_type ||
        "";

    const mimeType =
        analysis?.mime_type ||
        identification.mime_type ||
        "";


    let mimeMatch =
        identification.extension_mime_match;


    /*
       If the backend doesn't provide the match value,
       don't guess.
    */

    let mimeMatchDisplay = null;

    if (mimeMatch === true) {

        mimeMatchDisplay = `
            <span class="metadata-match metadata-match-good">
                MATCH
            </span>
        `;

    } else if (mimeMatch === false) {

        mimeMatchDisplay = `
            <span class="metadata-match metadata-match-warning">
                MISMATCH
            </span>
        `;

    } else {

        mimeMatchDisplay = `
            <span class="metadata-match metadata-match-neutral">
                NOT AVAILABLE
            </span>
        `;
    }


    /* ---------------------------------------------------------
       METADATA ITEMS
       --------------------------------------------------------- */

    const items = [

        {
            label: "ACCESS TIME",
            value: formatDate(
                filesystem.access_time
            )
        },

        {
            label: "MODIFICATION TIME",
            value: formatDate(
                filesystem.modification_time
            )
        },

        {
            label: "CREATION TIME",
            value: formatDate(
                filesystem.creation_time
            )
        },

        {
            label: "FILESYSTEM SIZE",
            value: formatSize(
                filesystem.file_size
            )
        },

        {
            label: "FORMAT",
            value: formatValue(
                formatSpecific.format ||
                metadata.format ||
                metadata.file_format
            )
        },

        {
            label: "MIME TYPE",
            value:
                cleanMetadataText(
                    mimeType
                )
        },

        {
            label: "DIMENSIONS",
            value: getDimensions()
        },

        {
            label: "COLOR MODE",
            value: formatValue(
                formatSpecific.mode ||
                formatSpecific.color_mode ||
                exif.ColorSpace
            )
        },

        
           {
    label: "TYPE CONSISTENCY",
    value: mimeMatchDisplay,
    html: true
}

    ];


    const availableItems =
        items.filter(item => {

            if (item.html) {
                return true;
            }

            return (
                item.value !== null &&
                item.value !== undefined &&
                item.value !== ""
            );
        });


    if (
        availableItems.length === 0
    ) {

        return `
            <div class="metadata-empty">

                <strong>
                    No metadata available
                </strong>

                <span>
                    No readable file metadata was found.
                </span>

            </div>
        `;
    }


    return availableItems
        .map(item => {

            return `
                <div class="metadata-item">

                    <div class="metadata-label">
                        ${escapeHTML(item.label)}
                    </div>

                    <div class="metadata-value">
                        ${
                            item.html
                                ? item.value
                                : escapeHTML(item.value)
                        }
                    </div>

                </div>
            `;

        })
        .join("");
}


/* =========================================================
   STRINGS
   ========================================================= */

function renderStrings(data) {

    if (
        !data ||
        typeof data !== "object"
    ) {
        return `
            <div class="result-empty result-empty-dark">

                <strong>
                    No meaningful strings extracted
                </strong>

                <span>
                    No printable strings were available for display.
                </span>

            </div>
        `;
    }


    let strings = [];


    if (
        Array.isArray(data.strings)
    ) {
        strings = data.strings;
    }


    if (
        !strings.length &&
        Array.isArray(data.extracted_strings)
    ) {
        strings =
            data.extracted_strings;
    }


    if (
        !strings.length &&
        Array.isArray(data.all_strings)
    ) {
        strings =
            data.all_strings;
    }


    if (
        !strings.length &&
        Array.isArray(data.results)
    ) {
        strings =
            data.results;
    }


    if (
        !strings.length &&
        data.suspicious_categories
    ) {

        Object.values(
            data.suspicious_categories
        ).forEach(categoryItems => {

            if (
                !Array.isArray(categoryItems)
            ) {
                return;
            }

            categoryItems.forEach(item => {

                if (
                    typeof item === "string"
                ) {

                    strings.push(item);

                } else if (
                    item &&
                    typeof item === "object"
                ) {

                    const value =
                        item.match ||
                        item.string ||
                        item.value ||
                        item.text ||
                        "";

                    if (value) {
                        strings.push(value);
                    }
                }

            });

        });
    }


    strings = strings.filter(item => {

        let value = "";


        if (
            typeof item === "string"
        ) {

            value = item;

        } else if (
            item &&
            typeof item === "object"
        ) {

            value =
                item.string ||
                item.match ||
                item.value ||
                item.text ||
                "";
        }


        const normalized =
            String(value)
                .trim()
                .toLowerCase();


        const isMetadataNamespace =
            normalized.startsWith(
                "http://ns.adobe.com/xap/1.0"
            )
            ||
            normalized.startsWith(
                "https://ns.adobe.com/xap/1.0"
            )
            ||
            normalized.startsWith(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns"
            )
            ||
            normalized.startsWith(
                "https://www.w3.org/1999/02/22-rdf-syntax-ns"
            );


        return !isMetadataNamespace;

    });


    const uniqueStrings = [];
    const seen = new Set();


    strings.forEach(item => {

        let value = "";


        if (
            typeof item === "string"
        ) {

            value = item;

        } else if (
            item &&
            typeof item === "object"
        ) {

            value =
                item.string ||
                item.match ||
                item.value ||
                item.text ||
                "";
        }


        value =
            String(value).trim();


        if (!value) {
            return;
        }


        const key =
            value.toLowerCase();


        if (!seen.has(key)) {

            seen.add(key);

            uniqueStrings.push(value);
        }

    });


    strings =
        uniqueStrings;


    if (!strings.length) {

        return `
            <div class="result-empty result-empty-dark">

                <strong>
                    No meaningful strings extracted
                </strong>

                <span>
                    No meaningful printable strings were found in this file.
                </span>

            </div>
        `;
    }


    const visibleStrings =
        strings.slice(0, 500);


    return `

        <div class="strings-header">

            <span>
                ${strings.length.toLocaleString()}
                STRINGS EXTRACTED
            </span>

            <span>
                SHOWING
                ${visibleStrings.length.toLocaleString()}
            </span>

        </div>


        <div class="strings-list">

            ${
                visibleStrings
                    .map(value => `
                        <div class="string-item">
                            ${escapeHTML(value)}
                        </div>
                    `)
                    .join("")
            }

        </div>

    `;
}


/* =========================================================
   FILE SIZE
   ========================================================= */

function formatFileSize(bytes) {

    if (
        !bytes ||
        bytes <= 0
    ) {
        return "0 B";
    }


    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];


    const index =
        Math.min(
            Math.floor(
                Math.log(bytes) /
                Math.log(1024)
            ),
            units.length - 1
        );


    return `${(
        bytes /
        Math.pow(1024, index)
    ).toFixed(2)} ${units[index]}`;
}


/* =========================================================
   RISK HELPERS
   ========================================================= */

function getRiskClass(level) {

    return `risk-${String(
        level
    ).toLowerCase()}`;
}


function getVerdictText(level) {

    const verdicts = {

        LOW:
            "Likely Safe",

        MEDIUM:
            "Suspicious",

        HIGH:
            "High Risk",

        CRITICAL:
            "Critical Risk"

    };


    return (
        verdicts[level] ||
        "Unknown"
    );
}