# Digital-Forensics-
Project on Disk Image
This repository contains a comprehensive report on the architecture of forensic disk image analysis, along with code examples that illustrate various stages of the process. The code is written in Python and includes snippets for image acquisition, metadata extraction, file system analysis, and more.
Introduction
Forensic disk image analysis is a crucial process in digital forensics, allowing investigators to examine storage devices for evidence. This repository provides a detailed report on the forensic analysis process.

Architecture Overview
The forensic disk image analysis process is divided into several key layers:

Image Acquisition Layer: Creating a bit-by-bit copy of the storage device.
\
Image Metadata Extraction Layer: Extracting metadata such as partition tables and disk signatures.
Partition Mounting Layer: Mounting identified partitions as virtual drives.
File System Analysis Layer: Scanning partitions for files and directories.
File Analysis Layer: Analyzing individual files for evidence.
Specific File Type Analysis Layer: Detailed examination of specific file types.
Reporting and Documentation Layer: Consolidating findings into structured reports.
Report Dissemination Layer: Sharing analysis results with stakeholders.
