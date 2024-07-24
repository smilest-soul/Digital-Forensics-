import os
import sys
import zipfile
import hashlib
import datetime
import sqlite3
import plistlib
import binascii
import re
import requests
import PyQt5.QtWidgets as QtWidgets
import PyQt5.QtCore as QtCore
import PyQt5.QtGui as QtGui

class AutopsyMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Autopsy")
        self.setGeometry(100, 100, 800, 600)

        # Create a status bar
        self.status_bar = QtWidgets.QStatusBar()
        self.setStatusBar(self.status_bar)

        # Create a central widget
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        # Create a layout for the central widget
        self.central_layout = QtWidgets.QVBoxLayout()
        self.central_widget.setLayout(self.central_layout)

        # Create a label for the image path
        self.image_path_label = QtWidgets.QLabel("Image Path:")
        self.central_layout.addWidget(self.image_path_label)

        # Create a line edit for the image path
        self.image_path_line_edit = QtWidgets.QLineEdit()
        self.central_layout.addWidget(self.image_path_line_edit)

        # Create a button to select the image path
        self.image_path_select_button = QtWidgets.QPushButton("Select")
        self.image_path_select_button.clicked.connect(self.select_image_path)
        self.central_layout.addWidget(self.image_path_select_button)

        # Create a label for the case name
        self.case_name_label = QtWidgets.QLabel("Case Name:")
        self.central_layout.addWidget(self.case_name_label)

        # Create a line edit for the case name
        self.case_name_line_edit = QtWidgets.QLineEdit()
        self.central_layout.addWidget(self.case_name_line_edit)

        # Create a label for the DD file information
        self.dd_info_label = QtWidgets.QLabel("DD File Information:")
        self.dd_info_label.setStyleSheet("color: blue; font-weight: bold;")
        self.central_layout.addWidget(self.dd_info_label)

        # Create a text edit to display DD file information
        self.dd_info_text_edit = QtWidgets.QTextEdit()
        self.dd_info_text_edit.setReadOnly(True)  # Make it read-only
        self.central_layout.addWidget(self.dd_info_text_edit)

        # Create a label for the findings
        self.findings_label = QtWidgets.QLabel("Findings:")
        self.central_layout.addWidget(self.findings_label)

        # Create a list widget for the findings
        self.findings_list_widget = QtWidgets.QListWidget()
        self.central_layout.addWidget(self.findings_list_widget)

        # Create a button to start the analysis
        self.start_button = QtWidgets.QPushButton("Start")
        self.start_button.clicked.connect(self.start_analysis)
        self.central_layout.addWidget(self.start_button)

        # Create a button to generate the report
        self.generate_report_button = QtWidgets.QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.central_layout.addWidget(self.generate_report_button)

        self.autopsy = None  # Store the Autopsy instance

    def select_image_path(self):
        image_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Disk Image", os.getcwd(), "Disk Images (*.dd *.dmg *.img)"
        )
        self.image_path_line_edit.setText(image_path)

        # Display DD file information
        self.display_dd_info(image_path)

    def display_dd_info(self, image_path):
        # Get DD file information
        file_size = os.path.getsize(image_path)
        creation_date = datetime.datetime.fromtimestamp(os.path.getctime(image_path))

        # Display DD file information in the text edit widget
        self.dd_info_text_edit.setPlainText(f"File Size: {file_size} bytes\nCreation Date: {creation_date}")

    def start_analysis(self):
        # Disable the start button to prevent multiple analyses
        self.start_button.setEnabled(False)

        # Get the image path and case name
        image_path = self.image_path_line_edit.text()
        case_name = self.case_name_line_edit.text()

        # Create an Autopsy instance
        self.autopsy = Autopsy(image_path, case_name)

        # Run the autopsy
        self.autopsy.run()

        # Enable the start button again
        self.start_button.setEnabled(True)

        # Display the findings in the list widget
        self.findings_list_widget.clear()
        for finding in self.autopsy.findings:
            item = QtWidgets.QListWidgetItem(finding)
            self.findings_list_widget.addItem(item)

    def generate_report(self):
        if self.autopsy:
            # Generate the report
            self.autopsy.generate_report(self.autopsy.case_name)

            # Display a message in the status bar
            self.status_bar.showMessage("Report generated successfully.")
        else:
            self.status_bar.showMessage("Please run the analysis first.")


class Autopsy:
    def __init__(self, image_path, case_name):
        self.image_path = image_path
        self.case_name = case_name
        self.case_path = os.path.join("cases", self.case_name)
        self.image_info = {}
        self.findings = []

    def scan_file_with_virustotal(self, file_path):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': '6c255c3b27736d2613d994f6e43a1da82b289e9e026f64ab560e18f61d1ade37'}
        files = {'file': (file_path, open(file_path, 'rb'))}

        response = requests.post(url, files=files, params=params)
        response_data = response.json()

        if response.status_code == 200:
            resource = response_data.get('resource')
            if resource:
                return resource
            else:
                print("Submission failed.")
        else:
            print("Submission failed.")

    def get_scan_report(self, resource):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': '6c255c3b27736d2613d994f6e43a1da82b289e9e026f64ab560e18f61d1ade37', 'resource': resource}

        response = requests.get(url, params=params)
        response_data = response.json()

        if response.status_code == 200:
            return response_data
        else:
            print("Failed to get scan report.")

    def extract_image_info(self):
        with open(self.image_path, "rb") as f:
            # Read the first 512 bytes of the image
            data = f.read(512)

            # Parse the MBR
            mbr = data[0:512]
            self.image_info["partition_table"] = mbr

            # Get the partition table entries
            partition_entries = []
            for i in range(4):
                offset = 0x1BE + (i * 0x10)
                entry = mbr[offset : offset + 16]
                partition_entries.append(entry)

            # Parse the partition entries
            self.image_info["partitions"] = []
            for entry in partition_entries:
                partition = {}
                partition["boot_ind"] = entry[0]
                partition["start_chs"] = (entry[1], entry[2], entry[3])
                partition["type"] = entry[4]
                partition["end_chs"] = (entry[5], entry[6], entry[7])
                partition["start_sector"] = (
                    partition["start_chs"][0] * 256 * 16
                    + partition["start_chs"][1] * 16
                    + partition["start_chs"][2]
                )
                partition["end_sector"] = (
                    partition["end_chs"][0] * 256 * 16
                    + partition["end_chs"][1] * 16
                    + partition["end_chs"][2]
                )
                self.image_info["partitions"].append(partition)

    def mount_partition(self, partition_index):
        partition = self.image_info["partitions"][partition_index]
        mount_path = os.path.join(
            self.case_path, "partitions", "partition{:02d}".format(partition_index)
        )
        os.makedirs(mount_path, exist_ok=True)

        # Mount the partition using the losetup command
        os.system(
            "losetup -o {} {} {}".format(
                partition["start_sector"] * 512, self.image_path, mount_path
            )
        )

        return mount_path

    def unmount_partition(self, mount_path):
        os.system("losetup -d {}".format(mount_path))

    def scan_partition(self, mount_path):
        # Create a list of file paths to scan
        files_to_scan = []
        for root, dirs, files in os.walk(mount_path):
            for file in files:
                file_path = os.path.join(root, file)
                files_to_scan.append(file_path)

        # Scan the files for evidence
        for file_path in files_to_scan:
            # Submit the file to VirusTotal for scanning
            resource = self.scan_file_with_virustotal(file_path)

            if resource:
                # Retrieve the scan report
                report = self.get_scan_report(resource)

                # Process the scan report and include results in findings or elsewhere in your report
                # For example, you can check if any antivirus engines flagged the file as malicious
                if report.get('positives', 0) > 0:
                    self.findings.append(f"File flagged as malicious by VirusTotal: {file_path}")

    def create_database(self):
        db_path = os.path.join(self.case_path, "case.db")
        self.db = sqlite3.connect(db_path)

    def analyze_zip_files(self):
        zip_files = []
        for root, dirs, files in os.walk(self.case_path):
            for file in files:
                if file.endswith(".zip"):
                    zip_files.append(os.path.join(root, file))

        for zip_file in zip_files:
            with zipfile.ZipFile(zip_file, "r") as zip_ref:
                zip_ref.extractall(self.case_path)
                self.findings.append(f"Extracted ZIP file: {zip_file}")

    def analyze_plist_files(self):
        plist_files = []
        for root, dirs, files in os.walk(self.case_path):
            for file in files:
                if file.endswith(".plist"):
                    plist_files.append(os.path.join(root, file))

        for plist_file in plist_files:
            with open(plist_file, "rb") as f:
                plist_data = plistlib.load(f)
                self.findings.append(f"Found plist file: {plist_file} with contents: {plist_data}")

    def run(self):
        os.makedirs(self.case_path, exist_ok=True)
        self.extract_image_info()

        for index, partition in enumerate(self.image_info["partitions"]):
            mount_path = self.mount_partition(index)
            self.scan_partition(mount_path)
            self.unmount_partition(mount_path)

        self.create_database()
        self.analyze_zip_files()
        self.analyze_plist_files()

    def generate_report(self, case_name):
        report_path = os.path.join(self.case_path, f"{case_name}_report.txt")
        with open(report_path, "w") as report_file:
            report_file.write(f"Case Name: {case_name}\n")
            report_file.write(f"Image Path: {self.image_path}\n")
            report_file.write("\n--- File System Information ---\n")
            for key, value in self.image_info.items():
                report_file.write(f"{key}: {value}\n")

            report_file.write("\n--- Findings ---\n")
            for finding in self.findings:
                report_file.write(f"{finding}\n")


if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = AutopsyMainWindow()
    window.show()
    sys.exit(app.exec_())
