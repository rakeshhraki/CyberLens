from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
    send_file,
    render_template
)

from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy.exc import IntegrityError

from reports.report_generator import generate_analysis_report

from analyzer.file_utils import (
    generate_random_filename,
    save_uploaded_file,
    validate_upload,
    cleanup_file
)

from analyzer.hashing import calculate_all_hashes
from analyzer.file_identification import identify_file
from analyzer.metadata import extract_metadata
from analyzer.strings import analyze_strings
from analyzer.entropy import analyze_entropy
from analyzer.pe_analyzer import perform_pe_analysis
from analyzer.indicators import detect_all_indicators
from analyzer.risk_engine import calculate_risk, generate_verdict

from database.models import db, Analysis


analysis_bp = Blueprint('analysis', __name__)


# =========================================================
# REMOVE BENIGN METADATA NAMESPACE URLS
# =========================================================

def remove_benign_metadata_indicators(indicators, analysis_data):
    """
    Remove URLs commonly found in normal JPEG/XMP metadata
    so they do not unnecessarily increase the malware risk score.
    """

    if not isinstance(indicators, dict):
        return indicators

    detected = indicators.get('detected_indicators', [])

    if not isinstance(detected, list):
        return indicators

    cleaned = []

    benign_metadata_hosts = (
        'ns.adobe.com',
        'www.w3.org'
    )

    benign_metadata_paths = (
        '/xap/1.0/',
        '/1999/02/22-rdf-syntax-ns'
    )

    for indicator in detected:

        if not isinstance(indicator, dict):
            cleaned.append(indicator)
            continue

        indicator_id = indicator.get('id', '')

        evidence = str(
            indicator.get('evidence', '')
        ).strip().lower()

        if indicator_id == 'IND-003':

            is_metadata_namespace = (
                any(
                    host in evidence
                    for host in benign_metadata_hosts
                )
                and
                any(
                    path in evidence
                    for path in benign_metadata_paths
                )
            )

            if is_metadata_namespace:
                continue

        cleaned.append(indicator)

    indicators['detected_indicators'] = cleaned

    return indicators


# =========================================================
# RESULT PAGE
# =========================================================

@analysis_bp.route('/result/<int:analysis_id>')
def result_page(analysis_id):

    analysis = Analysis.query.get(analysis_id)

    if not analysis:
        return "Analysis not found", 404

    return render_template(
        'result.html',
        analysis_id=analysis_id
    )


# =========================================================
# FILE UPLOAD + STATIC ANALYSIS
# =========================================================

@analysis_bp.route('/api/upload', methods=['POST'])
def upload_file():

    file_path = None

    try:

        # -------------------------------------------------
        # CHECK FILE
        # -------------------------------------------------

        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400

        file = request.files['file']

        if not file or file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400


        # -------------------------------------------------
        # VALIDATE UPLOAD
        # -------------------------------------------------

        is_valid, error_msg = validate_upload(
            file,
            file.filename
        )

        if not is_valid:
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400


        # -------------------------------------------------
        # SAVE FILE SECURELY
        # -------------------------------------------------

        random_filename = generate_random_filename(
            file.filename
        )

        file_path, file_size = save_uploaded_file(
            file,
            random_filename
        )


        # -------------------------------------------------
        # CALCULATE HASHES
        # -------------------------------------------------

        hashes = calculate_all_hashes(file_path)

        sha256 = hashes.get('sha256', '')
        sha1 = hashes.get('sha1', '')
        md5 = hashes.get('md5', '')

        if not sha256:

            if file_path:
                cleanup_file(file_path)
                file_path = None

            return jsonify({
                'success': False,
                'error': 'Unable to calculate file hash'
            }), 500


        # -------------------------------------------------
        # IMPORTANT
        #
        # DO NOT CHECK FOR DUPLICATES.
        #
        # Every upload creates a NEW investigation.
        #
        # Same filename + same content
        #     = NEW investigation
        #
        # Same filename + different content
        #     = NEW investigation
        #
        # Different filename + same content
        #     = NEW investigation
        #
        # -------------------------------------------------


        # -------------------------------------------------
        # FILE IDENTIFICATION
        # -------------------------------------------------

        identification = identify_file(
            file_path,
            file.filename
        )


        # -------------------------------------------------
        # METADATA
        # -------------------------------------------------

        metadata = extract_metadata(
            file_path,
            identification.get(
                'extension',
                ''
            )
        )


        # -------------------------------------------------
        # STRING ANALYSIS
        # -------------------------------------------------

        strings_analysis = analyze_strings(
            file_path,
            min_length=4
        )


        # -------------------------------------------------
        # ENTROPY
        # -------------------------------------------------

        entropy_analysis = analyze_entropy(
            file_path
        )


        # -------------------------------------------------
        # PE ANALYSIS
        # -------------------------------------------------

        pe_analysis = perform_pe_analysis(
            file_path
        )


        # -------------------------------------------------
        # COMBINE ANALYSIS DATA
        # -------------------------------------------------

        analysis_data = {
            'identification': identification,
            'metadata': metadata,
            'strings': strings_analysis,
            'entropy': entropy_analysis,
            'pe_analysis': pe_analysis
        }


        # -------------------------------------------------
        # DETECT INDICATORS
        # -------------------------------------------------

        indicators = detect_all_indicators(
            analysis_data
        )


        # -------------------------------------------------
        # REMOVE BENIGN JPEG/XMP METADATA URLS
        # -------------------------------------------------

        indicators = remove_benign_metadata_indicators(
            indicators,
            analysis_data
        )


        # -------------------------------------------------
        # MIME MISMATCH INDICATOR
        # -------------------------------------------------

        identification_data = analysis_data.get(
            'identification',
            {}
        )

        if not identification_data.get(
            'extension_mime_match',
            True
        ):

            detected_indicators = indicators.get(
                'detected_indicators',
                []
            )

            already_detected = any(
                isinstance(item, dict)
                and item.get('id') == 'IND-MIME-001'
                for item in detected_indicators
            )

            if not already_detected:

                detected_indicators.append({
                    'id': 'IND-MIME-001',
                    'name': 'Extension/MIME Type Mismatch',
                    'category': 'FILE_IDENTIFICATION',
                    'severity': 'MEDIUM',
                    'score': 10,
                    'evidence': identification_data.get(
                        'mime_mismatch_evidence',
                        'File extension does not match detected MIME type.'
                    )
                })

            indicators['detected_indicators'] = (
                detected_indicators
            )


        # -------------------------------------------------
        # STORE INDICATORS
        # -------------------------------------------------

        analysis_data['indicators'] = indicators


        # -------------------------------------------------
        # CALCULATE RISK
        # -------------------------------------------------

        risk = calculate_risk(
            analysis_data
        )


        # -------------------------------------------------
        # GENERATE VERDICT
        # -------------------------------------------------

        verdict = generate_verdict(
            risk
        )


        # -------------------------------------------------
        # FILE TYPE
        # -------------------------------------------------

        file_type = identification.get(
            'file_category',
            identification.get(
                'file_type',
                identification.get(
                    'description',
                    'Unknown'
                )
            )
        )


        # -------------------------------------------------
        # MIME TYPE
        # -------------------------------------------------

        mime_type = identification.get(
            'mime_type'
        )

        if not mime_type:
            mime_type = file.content_type


        # -------------------------------------------------
        # ENTROPY VALUE
        # -------------------------------------------------

        entropy_value = None

        if isinstance(
            entropy_analysis,
            dict
        ):

            entropy_value = entropy_analysis.get(
                'entropy'
            )


        # -------------------------------------------------
        # CREATE DATABASE RECORD
        # -------------------------------------------------

        analysis_record = Analysis(

            filename=file.filename,

            sha256=sha256,

            md5=md5,

            sha1=sha1,

            file_type=file_type,

            mime_type=mime_type,

            file_size=file_size,

            entropy=entropy_value,

            risk_score=risk.get(
                'score',
                0
            ),

            severity=risk.get(
                'risk_level',
                'LOW'
            ),

            indicators=indicators,

            analysis_data={

                'identification': identification,

                'metadata': metadata,

                'strings': strings_analysis,

                'entropy': entropy_analysis,

                'pe_analysis': pe_analysis,

                'risk': risk,

                'verdict': verdict

            }

        )


        # -------------------------------------------------
        # SAVE DATABASE RECORD
        # -------------------------------------------------

        db.session.add(
            analysis_record
        )

        db.session.commit()


        # -------------------------------------------------
        # CLEAN UP UPLOADED FILE
        # -------------------------------------------------

        if file_path:
            cleanup_file(file_path)
            file_path = None


        # -------------------------------------------------
        # SUCCESS RESPONSE
        # -------------------------------------------------

        return jsonify({

            'success': True,

            'message': 'File uploaded and analyzed successfully',

            'data': {

                'analysis_id': analysis_record.id,

                'original_filename': file.filename,

                'stored_filename': random_filename,

                'file_size': file_size,

                'content_type': file.content_type,

                'hashes': hashes,

                'identification': identification,

                'metadata': metadata,

                'strings': strings_analysis,

                'entropy': entropy_analysis,

                'pe_analysis': pe_analysis,

                'indicators': indicators,

                'risk': risk,

                'verdict': verdict

            }

        }), 201


    # =====================================================
    # FILE TOO LARGE
    # =====================================================

    except RequestEntityTooLarge:

        if file_path:
            cleanup_file(file_path)
            file_path = None

        max_mb = (
            current_app.config['MAX_CONTENT_LENGTH']
            / (1024 * 1024)
        )

        return jsonify({

            'success': False,

            'error': (
                f'File size exceeds maximum of {max_mb}MB'
            )

        }), 413


    # =====================================================
    # SECURITY ERROR
    # =====================================================

    except ValueError:

        db.session.rollback()

        if file_path:
            cleanup_file(file_path)
            file_path = None

        return jsonify({

            'success': False,

            'error': 'Security violation detected'

        }), 403


    # =====================================================
    # DATABASE ERROR
    # =====================================================

    except IntegrityError as e:

        db.session.rollback()

        if file_path:
            cleanup_file(file_path)
            file_path = None

        print(
            'DATABASE ERROR:',
            repr(e)
        )

        return jsonify({

            'success': False,

            'error': 'Unable to save analysis'

        }), 500


    # =====================================================
    # GENERAL ERROR
    # =====================================================

    except Exception as e:

        db.session.rollback()

        if file_path:
            cleanup_file(file_path)
            file_path = None

        print(
            'UPLOAD ERROR:',
            repr(e)
        )

        return jsonify({

            'success': False,

            'error': 'Internal server error during upload'

        }), 500


# =========================================================
# PDF REPORT
# =========================================================

@analysis_bp.route(
    '/api/report/<int:analysis_id>',
    methods=['GET']
)
def download_report(analysis_id):

    try:

        analysis = Analysis.query.get(
            analysis_id
        )

        if not analysis:

            return jsonify({

                'success': False,

                'error': 'Analysis not found'

            }), 404


        pdf_buffer = generate_analysis_report(
            analysis
        )


        filename = (
            f'cyberlens_report_{analysis.id}.pdf'
        )


        return send_file(

            pdf_buffer,

            mimetype='application/pdf',

            as_attachment=True,

            download_name=filename

        )


    except Exception as e:

        print(
            'REPORT ERROR:',
            repr(e)
        )

        return jsonify({

            'success': False,

            'error': 'Unable to generate report'

        }), 500