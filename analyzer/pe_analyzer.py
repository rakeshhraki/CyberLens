import math
from typing import Dict, List, Any, Optional

import pefile


def is_pe_file(file_path: str) -> bool:
    """
    Check if file is a valid PE file using pefile.
    Returns True if PE file can be parsed, False otherwise.
    """
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.close()
        return True

    except Exception:
        return False


def analyze_pe_file(
    file_path: str
) -> Optional[Dict[str, Any]]:
    """
    Perform comprehensive static PE file analysis.
    Returns None if file is not a valid PE file.
    """

    pe = None

    try:
        pe = pefile.PE(file_path)

        analysis = {
            "is_pe": True,
            "pe_type": None,
            "architecture": None,
            "entry_point": None,
            "image_base": None,
            "sections": [],
            "imports": [],
            "suspicious_apis": []
        }

        # Determine PE type
        if pe.is_exe():
            analysis["pe_type"] = "EXE"

        elif pe.is_dll():
            analysis["pe_type"] = "DLL"

        else:
            analysis["pe_type"] = "UNKNOWN"

        # Determine architecture
        if (
            pe.FILE_HEADER.Machine
            == pefile.MACHINE_TYPE[
                "IMAGE_FILE_MACHINE_I386"
            ]
        ):
            analysis["architecture"] = "x86 (32-bit)"

        elif (
            pe.FILE_HEADER.Machine
            == pefile.MACHINE_TYPE[
                "IMAGE_FILE_MACHINE_AMD64"
            ]
        ):
            analysis["architecture"] = "x64 (64-bit)"

        else:
            analysis["architecture"] = (
                f"Unknown ({pe.FILE_HEADER.Machine})"
            )

        # Entry point and image base
        if hasattr(pe, "OPTIONAL_HEADER"):

            analysis["entry_point"] = hex(
                pe.OPTIONAL_HEADER.AddressOfEntryPoint
            )

            analysis["image_base"] = hex(
                pe.OPTIONAL_HEADER.ImageBase
            )

        # Analyze sections
        if hasattr(pe, "sections"):

            for section in pe.sections:

                try:
                    section_name = (
                        section.Name
                        .decode(
                            "utf-8",
                            errors="replace"
                        )
                        .rstrip("\x00")
                    )

                except Exception:
                    section_name = "UNKNOWN"

                section_info = {
                    "name": section_name,

                    "virtual_address": hex(
                        section.VirtualAddress
                    ),

                    "virtual_size": (
                        section.Misc_VirtualSize
                    ),

                    "raw_size": (
                        section.SizeOfRawData
                    ),

                    "entropy": calculate_section_entropy(
                        file_path,
                        section
                    ),

                    "characteristics": (
                        section.Characteristics
                    ),

                    "is_executable": bool(
                        section.Characteristics
                        & 0x20000000
                    ),

                    "is_readable": bool(
                        section.Characteristics
                        & 0x40000000
                    ),

                    "is_writable": bool(
                        section.Characteristics
                        & 0x80000000
                    )
                }

                analysis["sections"].append(
                    section_info
                )

        # Analyze imports
        if hasattr(
            pe,
            "DIRECTORY_ENTRY_IMPORT"
        ):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                try:
                    dll_name = (
                        entry.dll
                        .decode(
                            "utf-8",
                            errors="replace"
                        )
                    )

                except Exception:
                    dll_name = "UNKNOWN"

                imports = []

                for imp in entry.imports:

                    if imp.name:

                        try:
                            api_name = (
                                imp.name
                                .decode(
                                    "utf-8",
                                    errors="replace"
                                )
                            )

                            imports.append(api_name)

                        except Exception:
                            continue

                analysis["imports"].append({
                    "dll": dll_name,
                    "functions": imports
                })

        # Check suspicious APIs
        analysis["suspicious_apis"] = (
            get_suspicious_apis(pe)
        )

        return analysis

    except Exception as e:

        return {
            "is_pe": False,
            "error": str(e),
            "note": (
                "File could not be parsed "
                "as a valid PE file"
            )
        }

    finally:

        if pe is not None:

            try:
                pe.close()

            except Exception:
                pass


def calculate_section_entropy(
    file_path: str,
    section
) -> float:
    """
    Calculate entropy of a specific PE section.
    """

    try:

        with open(
            file_path,
            "rb"
        ) as f:

            f.seek(
                section.PointerToRawData
            )

            data = f.read(
                section.SizeOfRawData
            )

        if not data:
            return 0.0

        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        total_bytes = len(data)

        entropy = 0.0

        for count in byte_counts:

            if count == 0:
                continue

            probability = (
                count / total_bytes
            )

            entropy -= (
                probability
                * math.log2(probability)
            )

        return entropy

    except Exception:
        return 0.0


def get_suspicious_apis(
    pe: pefile.PE
) -> List[Dict[str, str]]:
    """
    Check for suspicious API references.

    These are indicators only and are NOT proof
    that a file is malicious.
    """

    suspicious_api_list = [
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "WinExec",
        "ShellExecute",
        "ShellExecuteEx",
        "URLDownloadToFile",
        "InternetOpen",
        "InternetOpenUrl",
        "HttpSendRequest",
        "CreateProcess",
        "CreateProcessA",
        "CreateProcessW",
        "RegCreateKey",
        "RegSetValue",
        "RegOpenKey",
        "SetWindowsHookEx",
        "GetProcAddress",
        "LoadLibrary"
    ]

    found_apis = []

    if not hasattr(
        pe,
        "DIRECTORY_ENTRY_IMPORT"
    ):
        return found_apis

    for entry in pe.DIRECTORY_ENTRY_IMPORT:

        try:
            dll_name = (
                entry.dll
                .decode(
                    "utf-8",
                    errors="replace"
                )
            )

        except Exception:
            dll_name = "UNKNOWN"

        for imp in entry.imports:

            if not imp.name:
                continue

            try:
                api_name = (
                    imp.name
                    .decode(
                        "utf-8",
                        errors="replace"
                    )
                )

            except Exception:
                continue

            if api_name in suspicious_api_list:

                found_apis.append({
                    "api": api_name,
                    "dll": dll_name,
                    "note": (
                        "Suspicious API reference "
                        "detected. Requires analyst "
                        "investigation."
                    )
                })

    return found_apis


def analyze_pe_sections(
    sections: List[Dict]
) -> Dict[str, Any]:
    """
    Analyze PE sections for suspicious
    characteristics.
    """

    analysis = {
        "total_sections": len(sections),
        "executable_sections": [],
        "writable_executable_sections": [],
        "high_entropy_sections": [],
        "suspicious_section_names": []
    }

    suspicious_names = [
        ".text",
        ".data",
        ".rdata",
        ".bss",
        ".idata"
    ]

    for section in sections:

        # Executable sections
        if section.get("is_executable"):
            analysis[
                "executable_sections"
            ].append(
                section.get("name", "UNKNOWN")
            )

        # Writable + executable
        if (
            section.get("is_writable")
            and section.get("is_executable")
        ):

            analysis[
                "writable_executable_sections"
            ].append(
                section.get("name", "UNKNOWN")
            )

        # High entropy
        if section.get("entropy", 0) > 6.0:

            analysis[
                "high_entropy_sections"
            ].append({
                "name": section.get(
                    "name",
                    "UNKNOWN"
                ),
                "entropy": round(
                    section.get(
                        "entropy",
                        0
                    ),
                    2
                )
            })

        # Unusual section names
        section_name = section.get(
            "name",
            "UNKNOWN"
        )

        if section_name not in suspicious_names:

            analysis[
                "suspicious_section_names"
            ].append(section_name)

    return analysis


def perform_pe_analysis(
    file_path: str
) -> Dict[str, Any]:
    """
    Perform complete static PE analysis.

    Returns analysis results or a non-PE
    result if the file is not a valid PE.
    """

    # Check if file is PE
    if not is_pe_file(file_path):

        return {
            "is_pe": False,
            "note": (
                "File is not a valid PE file "
                "(Windows executable/DLL)"
            )
        }

    # Analyze PE
    pe_analysis = analyze_pe_file(
        file_path
    )

    if (
        pe_analysis is None
        or not pe_analysis.get(
            "is_pe",
            False
        )
    ):

        return {
            "is_pe": False,
            "note": (
                "PE file analysis failed "
                "or file is not a valid PE"
            )
        }

    # Analyze sections
    if (
        pe_analysis.get("is_pe")
        and pe_analysis.get("sections")
    ):

        section_analysis = (
            analyze_pe_sections(
                pe_analysis["sections"]
            )
        )

        pe_analysis[
            "section_analysis"
        ] = section_analysis

    return pe_analysis