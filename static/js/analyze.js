document.addEventListener('DOMContentLoaded', function () {

    const uploadZone =
        document.getElementById('upload-zone');

    const fileInput =
        document.getElementById('file-input');

    const chooseFileBtn =
        document.getElementById('choose-file-btn');

    const fileActionBtn =
        document.getElementById('file-action-btn');

    const selectedFileCard =
        document.getElementById('selected-file-card');

    const selectedFileName =
        document.getElementById('selected-file-name');

    const selectedFileMeta =
        document.getElementById('selected-file-meta');

    const removeFileBtn =
        document.getElementById('remove-file-btn');

    const analysisAction =
        document.getElementById('analysis-action');

    const startAnalysisBtn =
        document.getElementById('start-analysis-btn');

    const analysisStages =
        document.getElementById('analysis-stages');

    const analyzeError =
        document.getElementById('analyze-error');

    const errorMessage =
        document.getElementById('error-message');

    const progressState =
        document.getElementById('progress-state');

    const progressLineFill =
        document.getElementById('progress-line-fill');


    const allowedExtensions = [
        'pdf',
        'doc',
        'docx',
        'jpg',
        'jpeg',
        'png',
        'txt'
    ];

    const maxFileSize = 8 * 1024 * 1024;

    let selectedFile = null;
    let isAnalyzing = false;


    /* =====================================================
       CHOOSE FILE BUTTON
       ===================================================== */

    chooseFileBtn.addEventListener('click', function (event) {

        event.preventDefault();

        if (isAnalyzing) {
            return;
        }

        fileInput.click();

    });


    /* =====================================================
       FILE ICON BUTTON
       ===================================================== */

    if (fileActionBtn) {

        fileActionBtn.addEventListener('click', function (event) {

            event.preventDefault();
            event.stopPropagation();

            if (isAnalyzing) {
                return;
            }

            fileInput.click();

        });

    }


    /* =====================================================
       KEYBOARD ACCESS
       ===================================================== */

    uploadZone.addEventListener('keydown', function (event) {

        if (
            event.key === 'Enter' ||
            event.key === ' '
        ) {

            event.preventDefault();

            if (!isAnalyzing) {
                fileInput.click();
            }

        }

    });


    /* =====================================================
       FILE INPUT
       ===================================================== */

    fileInput.addEventListener('change', function () {

        if (fileInput.files.length > 0) {

            handleFile(
                fileInput.files[0]
            );

        }

    });


    /* =====================================================
       DRAG OVER
       ===================================================== */

    uploadZone.addEventListener('dragover', function (event) {

        event.preventDefault();

        if (isAnalyzing) {
            return;
        }

        uploadZone.classList.add(
            'drag-active'
        );

    });


    /* =====================================================
       DRAG LEAVE
       ===================================================== */

    uploadZone.addEventListener('dragleave', function (event) {

        event.preventDefault();

        uploadZone.classList.remove(
            'drag-active'
        );

    });


    /* =====================================================
       DROP
       ===================================================== */

    uploadZone.addEventListener('drop', function (event) {

        event.preventDefault();

        uploadZone.classList.remove(
            'drag-active'
        );

        if (isAnalyzing) {
            return;
        }

        if (event.dataTransfer.files.length > 0) {

            handleFile(
                event.dataTransfer.files[0]
            );

        }

    });


    /* =====================================================
       REMOVE FILE
       ===================================================== */

    removeFileBtn.addEventListener('click', function () {

        if (isAnalyzing) {
            return;
        }

        resetFileSelection();

    });


    /* =====================================================
       START ANALYSIS
       ===================================================== */

    startAnalysisBtn.addEventListener('click', function () {

        if (
            !selectedFile ||
            isAnalyzing
        ) {
            return;
        }

        uploadFile(
            selectedFile
        );

    });


    /* =====================================================
       FILE VALIDATION
       ===================================================== */

    function handleFile(file) {

        hideError();

        const extension =
            file.name
                .split('.')
                .pop()
                .toLowerCase();


        if (
            !allowedExtensions.includes(
                extension
            )
        ) {

            showError(
                'File type not allowed. Supported types: ' +
                allowedExtensions.join(', ')
            );

            return;
        }


        if (
            file.size > maxFileSize
        ) {

            showError(
                'File size exceeds the maximum limit of 8 MB.'
            );

            return;
        }


        if (
            file.size === 0
        ) {

            showError(
                'The selected file is empty.'
            );

            return;
        }


        selectedFile = file;

        displaySelectedFile(
            file
        );

    }


    /* =====================================================
       DISPLAY SELECTED FILE
       ===================================================== */

    function displaySelectedFile(file) {

        const extension =
            file.name
                .split('.')
                .pop()
                .toUpperCase();


        selectedFileName.textContent =
            file.name;


        selectedFileMeta.textContent =
            formatFileSize(file.size) +
            ' · ' +
            extension;


        selectedFileCard.style.display =
            'flex';


        analysisAction.style.display =
            'flex';


        uploadZone.classList.add(
            'file-selected'
        );

    }


    /* =====================================================
       UPLOAD / ANALYSIS
       ===================================================== */

    function uploadFile(file) {

        isAnalyzing = true;

        hideError();

        disableInterface();

        analysisStages.style.display =
            'block';

        resetStages();

        simulateProgress();


        const formData =
            new FormData();


        formData.append(
            'file',
            file
        );


        fetch(
            '/api/upload',
            {
                method: 'POST',
                body: formData
            }
        )

        .then(async response => {

            let data;

            try {

                data =
                    await response.json();

            } catch (error) {

                throw new Error(
                    'The server returned an invalid response.'
                );

            }


            if (
                !response.ok ||
                !data.success
            ) {

                throw new Error(
                    data.error ||
                    'Analysis failed.'
                );

            }


            return data;

        })

        .then(data => {

            const analysisId =
                data.data &&
                data.data.analysis_id;


            if (!analysisId) {

                throw new Error(
                    'Analysis ID was not returned by the server.'
                );

            }


            completeProgress();


            setTimeout(function () {

                window.location.href =
                    `/result/${analysisId}`;

            }, 500);

        })

        .catch(error => {

            console.error(
                'Analysis error:',
                error
            );


            isAnalyzing = false;

            enableInterface();


            analysisStages.style.display =
                'none';


            showError(
                error.message ||
                'Internal server error during upload.'
            );

        });

    }


    /* =====================================================
       PROGRESS DISPLAY
       ===================================================== */

    function simulateProgress() {

        const stages = [
            'stage-01',
            'stage-02',
            'stage-03',
            'stage-04',
            'stage-05',
            'stage-06',
            'stage-07',
            'stage-08',
            'stage-09'
        ];


        let currentStage = 0;


        progressLineFill.style.width =
            '0%';


        const interval =
            setInterval(function () {

                if (!isAnalyzing) {

                    clearInterval(
                        interval
                    );

                    return;

                }


                if (currentStage > 0) {

                    const previousStage =
                        document.getElementById(
                            stages[currentStage - 1]
                        );


                    if (previousStage) {

                        setStageComplete(
                            previousStage
                        );

                    }

                }


                if (
                    currentStage <
                    stages.length
                ) {

                    const current =
                        document.getElementById(
                            stages[currentStage]
                        );


                    if (current) {

                        setStageActive(
                            current
                        );

                    }


                    const percentage =
                        (
                            (currentStage + 1) /
                            stages.length
                        ) * 100;


                    progressLineFill.style.width =
                        percentage + '%';


                    currentStage++;

                }

            }, 350);

    }


    /* =====================================================
       COMPLETE PROGRESS
       ===================================================== */

    function completeProgress() {

        const stages =
            document.querySelectorAll(
                '#analysis-stages .stage'
            );


        stages.forEach(function (stage) {

            setStageComplete(
                stage
            );

        });


        progressLineFill.style.width =
            '100%';


        progressState.textContent =
            'COMPLETE';

    }


    /* =====================================================
       RESET PROGRESS
       ===================================================== */

    function resetStages() {

        const stages =
            document.querySelectorAll(
                '#analysis-stages .stage'
            );


        stages.forEach(function (stage) {

            stage.classList.remove(
                'active',
                'complete'
            );


            const status =
                stage.querySelector(
                    '.stage-status'
                );


            if (status) {

                status.textContent =
                    'PENDING';

            }

        });


        progressState.textContent =
            'PROCESSING';


        progressLineFill.style.width =
            '0%';

    }


    /* =====================================================
       ACTIVE STAGE
       ===================================================== */

    function setStageActive(stage) {

        stage.classList.remove(
            'complete'
        );


        stage.classList.add(
            'active'
        );


        const status =
            stage.querySelector(
                '.stage-status'
            );


        if (status) {

            status.textContent =
                'RUNNING';

        }

    }


    /* =====================================================
       COMPLETE STAGE
       ===================================================== */

    function setStageComplete(stage) {

        stage.classList.remove(
            'active'
        );


        stage.classList.add(
            'complete'
        );


        const status =
            stage.querySelector(
                '.stage-status'
            );


        if (status) {

            status.textContent =
                'COMPLETE';

        }

    }


    /* =====================================================
       DISABLE INTERFACE
       ===================================================== */

    function disableInterface() {

        chooseFileBtn.disabled =
            true;

        if (fileActionBtn) {
            fileActionBtn.disabled =
                true;
        }

        removeFileBtn.disabled =
            true;

        startAnalysisBtn.disabled =
            true;


        uploadZone.classList.add(
            'analysis-running'
        );


        startAnalysisBtn.innerHTML =
            'Analyzing <span class="button-spinner"></span>';

    }


    /* =====================================================
       ENABLE INTERFACE
       ===================================================== */

    function enableInterface() {

        chooseFileBtn.disabled =
            false;

        if (fileActionBtn) {
            fileActionBtn.disabled =
                false;
        }

        removeFileBtn.disabled =
            false;

        startAnalysisBtn.disabled =
            false;


        uploadZone.classList.remove(
            'analysis-running'
        );


        startAnalysisBtn.innerHTML =
            'Start Analysis <span>→</span>';

    }


    /* =====================================================
       RESET FILE SELECTION
       ===================================================== */

    function resetFileSelection() {

        selectedFile = null;


        fileInput.value =
            '';


        selectedFileCard.style.display =
            'none';


        analysisAction.style.display =
            'none';


        uploadZone.classList.remove(
            'file-selected'
        );


        hideError();

    }


    /* =====================================================
       ERROR HANDLING
       ===================================================== */

    function showError(message) {

        errorMessage.textContent =
            message;


        analyzeError.style.display =
            'flex';


        analyzeError.scrollIntoView({
            behavior: 'smooth',
            block: 'nearest'
        });

    }


    function hideError() {

        analyzeError.style.display =
            'none';


        errorMessage.textContent =
            '';

    }


    /* =====================================================
       FILE SIZE
       ===================================================== */

    function formatFileSize(bytes) {

        if (bytes < 1024) {

            return bytes + ' B';

        }


        if (
            bytes <
            1024 * 1024
        ) {

            return (
                (bytes / 1024).toFixed(1) +
                ' KB'
            );

        }


        return (
            (bytes / (1024 * 1024)).toFixed(2) +
            ' MB'
        );

    }

});