from PyQt5 import QtGui
from PyQt5.QtGui import QIcon,QPixmap
from PyQt5.QtWidgets import QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QApplication, QTableWidget, \
    QTableWidgetItem, QLabel, QGroupBox, QLineEdit, QFormLayout, QGridLayout, QTabWidget, QComboBox
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QWidget, QAction, QTabWidget, QVBoxLayout, \
    QGroupBox, QHBoxLayout, QPlainTextEdit, QLineEdit, QLabel
import sys           #for system info
import platform      #for architecture , processor etc
import os            #for operating system informtion
import socket        #for hostname
import re, uuid      #for MAC conersion
import netifaces as ni

class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = "Footprinting : Rise and Fall in Network"
        self.setWindowTitle(self.title)
        self.setGeometry(0,0,1124,700)

        self.table_widget = MyTableWidget(self)
        self.setCentralWidget(self.table_widget)
        self.setStyleSheet("background-color:  #34495e  ;color:white;")

class MyTableWidget(QWidget):

    def __init__(self, parent):
        super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tab4 = QWidget()
        #self.tabs.resize(300, 200)

        self.tabs.setStyleSheet("font-size:15px;color:white;")
        # Add tabs
        self.tabs.addTab(self.tab1, " Host Information ")
        self.tabs.addTab(self.tab2, " Network Scanner ")
        self.tabs.addTab(self.tab3, " Vulnerability Scanner and Port Scanning")
        #self.tabs.addTab(self.tab4, " Port Scanner ")

        #********************************************************************
        #                   START-Tab1 - HOST Scanner                       *
        #********************************************************************
        # Create first tab
        self.tab1_groupBox1 = QGroupBox()
        self.tab1_groupBox2 = QGroupBox()
        self.tab1_groupBox3 = QGroupBox()
        self.tab1_groupBox4 = QGroupBox()
        self.tab1_groupBox5 = QGroupBox()
        self.tab1_groupBox_top = QGroupBox()
        self.tab1_groupBox_bottom = QGroupBox()

        self.tab1_layout1 = QHBoxLayout()
        self.tab1_layout1.addWidget(self.tab1_groupBox1,30)
        self.tab1_layout1.addWidget(self.tab1_groupBox2, 50)
        self.tab1_layout1.addWidget(self.tab1_groupBox3, 20)
        self.tab1_groupBox_top.setLayout(self.tab1_layout1)

        self.tab1_layout2 = QHBoxLayout()
        self.tab1_layout2.addWidget(self.tab1_groupBox4,40)
        self.tab1_layout2.addWidget(self.tab1_groupBox5, 60)
        self.tab1_groupBox_bottom.setLayout(self.tab1_layout2)

        self.tab1_layout_parent = QVBoxLayout()
        self.tab1_layout_parent.addWidget(self.tab1_groupBox_top,30)
        self.tab1_layout_parent.addWidget(self.tab1_groupBox_bottom, 70)

        self.tab1.setLayout(self.tab1_layout_parent)
        #**********styling***************
        self.tab1_groupBox1.setStyleSheet("background-color:rgba(46, 64, 83,100%);border:none;")
        self.tab1_groupBox2.setStyleSheet("background-color:rgba(46, 64, 83,100%);border:none;")
        self.tab1_groupBox3.setStyleSheet("background-color:rgba(46, 64, 83,100%);border:none;")
        self.tab1_groupBox4.setStyleSheet("background-color:rgba(46, 64, 83,100%);border:none;")
        self.tab1_groupBox5.setStyleSheet("background-color:rgba(46, 64, 83,100%);border:none;")
        self.tab1_groupBox_top.setStyleSheet("background-color:rgba(46, 64, 83,60%);border:none;border-radius:10px;")
        self.tab1_groupBox_bottom.setStyleSheet("background-color:rgba(46, 64, 83,70%);border:none;")
        self.tab1.setStyleSheet("background-color:rgba(  46, 64, 83,70%);")

        self.host_ip=""

        self.tableWidget = QTableWidget()
        # tableWidget.setRowCount(3)
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setColumnWidth(0, 80)
        self.tableWidget.setColumnWidth(1, 184)
        self.tableWidget.setColumnWidth(2, 184)
        self.tableWidget.setColumnWidth(3, 184)
        self.tableWidget.setHorizontalHeaderLabels(('SNo.','Interface', 'IP'))

        self.interface = ni.interfaces()
        c = 0

        for inter in self.interface:
            ni.ifaddresses(inter)
            self.tableWidget.insertRow(c)
            #print(str(inter))

            try:
                self.ip = ni.ifaddresses(inter)[ni.AF_INET][0]['addr']
                self.tableWidget.setItem(c, 0, QTableWidgetItem())
                self.tableWidget.setItem(c, 1, QTableWidgetItem(inter))
                self.tableWidget.setItem(c, 2, QTableWidgetItem(self.ip))
                if (str(inter) == str("wlo1")):
                    self.host_ip=self.ip
            except:
                self.tableWidget.setItem(c, 0, QTableWidgetItem())
                self.tableWidget.setItem(c, 1, QTableWidgetItem(inter))
                self.tableWidget.setItem(c, 2, QTableWidgetItem("No IP"))
            c = c + 1
        self.tab1_groupBox5_layout=QHBoxLayout()
        self.tab1_groupBox5_layout.addWidget(self.tableWidget)
        self.tab1_groupBox5.setLayout(self.tab1_groupBox5_layout)
        self.tableWidget.setStyleSheet("color:white;font-size:15px;background-color: #34495e;   ")

        self.IP_label = QLabel()
        self.IP_label.setText(self.host_ip)
        self.IP_label.setStyleSheet("color: white ;font-size:60px; border-radius:20px;padding:10%; background-color: #34495e;border-bottom:2px solid white;")
        self.MAC_label = QLabel()
        self.MAC_label.setText(str(':'.join(re.findall('..', '%012x' % uuid.getnode()))))
        self.MAC_label.setStyleSheet("color:#9b59b6  ;font-size:35px; border-radius:20px;padding-left:70%; background-color: #34495e ; border-bottom:2px solid white;")
        self.tab1_groupBox_top_groupBox1_Layout = QVBoxLayout()
        self.tab1_groupBox_top_groupBox1_Layout.addWidget(self.IP_label)
        self.tab1_groupBox_top_groupBox1_Layout.addWidget(self.MAC_label)
        self.tab1_groupBox1.setLayout(self.tab1_groupBox_top_groupBox1_Layout)

        self.IP_Calc = QLabel()
        self.IP_to_cal = "ipcalc " + self.IP_label.text()
        o = os.popen(str(self.IP_to_cal)).read()

        print(o)
        print(str(o))
        self.IP_Calc.setText(o)

        self.tab1_groupBox_top_groupBox2_Layout=QVBoxLayout()
        self.tab1_groupBox_top_groupBox2_Layout.addWidget(self.IP_Calc)
        self.tab1_groupBox2.setLayout(self.tab1_groupBox_top_groupBox2_Layout)
        self.IP_Calc.setStyleSheet("font-size:12px;  text-align: center;color: #48c9b0 ;border-left:2px solid white;border-right:2px solid white;padding-left:60%;margin:0px;border-radius:20px;background-color: #34495e ;")

        #*********logo*****************
        os_img = QLabel(self)
        pixmap = QPixmap('os_ubuntu.png')
        pixmap1 = pixmap.scaled(180,180)
        os_img.setPixmap(pixmap1)
        os_img.setStyleSheet("")
        self.tab1_groupBox_top_groupBox3_Layout=QVBoxLayout()
        self.tab1_groupBox_top_groupBox3_Layout.addWidget(os_img)
        self.tab1_groupBox3.setLayout(self.tab1_groupBox_top_groupBox3_Layout)
        #********************************

        self.tab1_groupBox_bottom_groupBox4_layout = QGridLayout()

        self.os_name_label = QLabel('OS Name')
        self.os_version_label = QLabel('OS Version')
        self.hostname_label = QLabel('Hostname')
        self.user_label = QLabel('UserLogin')
        self.processor_label = QLabel('Processor')
        self.architecture_label = QLabel('Architecture')

        self.os_name_text = QLineEdit(platform.system())
        self.os_version_text = QLineEdit(platform.release())
        self.hostname_text = QLineEdit(socket.gethostname())
        self.user_text = QLineEdit(os.getlogin())
        self.processor_text = QLineEdit(platform.processor())
        self.architecture_text = QLineEdit(str(platform.architecture()))

        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.os_name_label,0,0)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.os_version_label, 1, 0)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.hostname_label, 2, 0)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.user_label, 3, 0)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.processor_label, 4, 0)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.architecture_label, 5, 0)

        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.os_name_text,0,1)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.os_version_text, 1, 1)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.hostname_text, 2, 1)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.user_text, 3, 1)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.processor_text, 4, 1)
        self.tab1_groupBox_bottom_groupBox4_layout.addWidget(self.architecture_text, 5, 1)

        self.tab1_groupBox4.setLayout(self.tab1_groupBox_bottom_groupBox4_layout)

        #styling
        self.os_name_label.setStyleSheet("padding:10px;margin:0px;border-radius:10px;background-color: #34495e; color:white;border-left:1px solid  #ecf0f1 ;border-right:1px solid  #ecf0f1 ;")
        self.os_version_label.setStyleSheet("padding:10px;margin:0px;border-radius:10px;background-color: #34495e; color:white;border-left:1px solid  #ecf0f1 ;border-right:1px solid  #ecf0f1 ;")
        self.hostname_label.setStyleSheet("padding:10px;margin:0px;border-radius:10px;background-color: #34495e; color:white;border-left:1px solid  #ecf0f1 ;border-right:1px solid  #ecf0f1 ;")
        self.user_label.setStyleSheet("padding:10px;margin:0px;border-radius:10px;background-color: #34495e; color:white;border-left:1px solid  #ecf0f1 ;border-right:1px solid  #ecf0f1 ;")
        self.processor_label.setStyleSheet("padding:10px;margin:0px;border-radius:10px;background-color: #34495e; color:white;border-left:1px solid  #ecf0f1 ;border-right:1px solid  #ecf0f1 ;")
        self.architecture_label.setStyleSheet("padding:10px;margin:0px;border-radius:10px;background-color: #34495e; color:white;border-left:1px solid  #ecf0f1 ;border-right:1px solid  #ecf0f1 ;")

        self.os_name_text.setStyleSheet("padding:10px; padding-left:20%;margin:0px;border-radius:10px;background-color: #34495e     ; color:white;border-bottom:1px solid  #e74c3c ;")
        self.os_version_text.setStyleSheet("padding:10px; padding-left:20%;margin:0px;border-radius:10px;background-color: #34495e     ; color:white;border-bottom:1px solid  #e74c3c ;")
        self.hostname_text.setStyleSheet("padding:10px; padding-left:20%;margin:0px;border-radius:10px;background-color: #34495e     ; color:white;border-bottom:1px solid  #e74c3c ;")
        self.user_text.setStyleSheet("padding:10px; padding-left:20%;margin:0px;border-radius:10px;background-color: #34495e     ; color:white;border-bottom:1px solid  #e74c3c ;")
        self.processor_text.setStyleSheet("padding:10px; padding-left:20%;margin:0px;border-radius:10px;background-color: #34495e     ; color:white;border-bottom:1px solid  #e74c3c ;")
        self.architecture_text.setStyleSheet("padding:10px; padding-left:20%;margin:0px;border-radius:10px;background-color: #34495e     ; color:white;border-bottom:1px solid  #e74c3c ;")



        #********************************************************************
        #                   END-Tab1 - HOST Scanner                       *
        #********************************************************************
        #********************************************************************
        #                   Start-Tab2 - NETWORK Scanner              *
        #********************************************************************
        #Grouping tab3
        self.tab2_groupBox1 = QGroupBox()
        self.tab2_groupBox2 = QGroupBox()
        self.layout1 = QVBoxLayout(self)
        self.layout1.addWidget(self.tab2_groupBox1, 10)
        self.layout1.addWidget(self.tab2_groupBox2, 90)
        self.tab2.setLayout(self.layout1)

        self.layout2 = QHBoxLayout()
        self.ip_range_start = QLineEdit()
        self.ip_range_end = QLineEdit()
        self.scan_btn = QPushButton("Scan")
        self.hide_ele=QLabel()
        self.layout2.addWidget(self.ip_range_start, 15)
        self.layout2.addWidget(self.ip_range_end, 15)
        self.layout2.addWidget(self.hide_ele, 15)
        self.layout2.addWidget(self.scan_btn, 20)
        self.tab2_groupBox1.setLayout(self.layout2)

        #STYLING tab
        #tab3_groupBox1 Styling
        self.tab2_groupBox1.setStyleSheet("background-color:rgba(46, 64, 83,100%);")
        self.ip_range_start.setStyleSheet("font-size:15px;padding:8px;border-radius:10px;border: 1px solid white;color:white;")
        self.ip_range_end.setStyleSheet("font-size:15px;padding:8px;border-radius:10px;border: 1px solid white;color:white;")
        self.scan_btn.setStyleSheet("font-size:15px;padding:8px;border-radius:10px;border: 1px solid white;color:white;")
        self.ip_range_start.setPlaceholderText("IP Range Start ")
        self.ip_range_end.setPlaceholderText("IP Range End ")

        #tab3_groupBox2 Styling
        self.tab2_groupBox2.setStyleSheet("background-color:#273746 ;")
        self.tab2_groupBox1.setFlat(True)
        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

        ##add table to tab3_groupbox2
        self.tableWidget2 = QTableWidget()
        # tableWidget.setRowCount(3)
        self.tableWidget2.setColumnCount(5)
        self.tableWidget2.setColumnWidth(0, 80)
        self.tableWidget2.setColumnWidth(1, 250)
        self.tableWidget2.setColumnWidth(2, 350)
        self.tableWidget2.setColumnWidth(3, 291)
        self.tableWidget2.setColumnWidth(4, 291)
        self.tableWidget2.setStyleSheet("color:white;font-size:15px;")
           # tableWidget.setRowCount(3)
        self.tableWidget2.setHorizontalHeaderLabels(('SNo.', 'IP', 'MAC - Vendor','NetBios','OS'))
        self.table_layout = QVBoxLayout()
        self.table_layout.addWidget(self.tableWidget2)
        self.tab2_groupBox2.setLayout(self.table_layout)

        #clicked events
        self.scan_btn.clicked.connect(self.network_scanner)

        #********************************************************************
        #                   END-Tab2 - NETWORK Scanner              *
        #********************************************************************

        #********************************************************************
        #                   Start-Tab3 - VULNERABILITY Scanner              *
        #********************************************************************
        # Grouping tab3
        self.tab3_groupBox1 = QGroupBox()
        self.tab3_groupBox2 = QGroupBox()
        self.layout3 = QVBoxLayout(self)
        self.layout3.addWidget(self.tab3_groupBox1, 10)
        self.layout3.addWidget(self.tab3_groupBox2, 90)
        self.tab3.setLayout(self.layout3)

        self.layout4 = QHBoxLayout()
        self.target_ip = QLineEdit()
        self.scan_btn_vul = QPushButton("Scan Vulnerability")
        self.cb = QComboBox()
        self.cb.addItem(" ")
        self.cb.addItem("nmap -Pn -d --script vuln")
        self.cb.addItem("nmap --script exploit -Pn")
        self.cb.addItem("nmap --script brute -Pn")
        self.cb.addItem("nmap -A -T4")
        self.cb.addItem("nmap -O")
        self.cb.addItem("nmap --script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -sV -p21")
        self.cb.currentIndexChanged.connect(self.selectionchange)
        self.hide_ele1 = QLabel()
        self.layout4.addWidget(self.target_ip, 25)
        self.layout4.addWidget(self.cb, 25)
        self.layout4.addWidget(self.hide_ele1, 15)
        self.layout4.addWidget(self.scan_btn_vul, 20)
        self.tab3_groupBox1.setLayout(self.layout4)

        self.result = QPlainTextEdit()
        self.result.setPlaceholderText("Set IP")
        self.layout5=QHBoxLayout()
        self.layout5.addWidget(self.result)
        self.tab3_groupBox2.setLayout(self.layout5)

        # STYLING tab
        # tab3_groupBox1 Styling
        self.tab3_groupBox1.setStyleSheet("background-color:rgba(46, 64, 83,100%);")
        self.target_ip.setStyleSheet("font-size:15px;padding:8px;border-radius:10px;border: 1px solid white;color:white;")
        self.scan_btn_vul.setStyleSheet("font-size:15px;padding:8px;border-radius:10px;border: 1px solid white;color:white;")
        self.target_ip.setPlaceholderText("Target IP")
        self.cb.setStyleSheet("font-size:15px;background:rgba(46, 64, 83,90%);padding:8px;")

        # tab3_groupBox2 Styling
        self.tab3_groupBox2.setStyleSheet("background-color:#273746 ;")
        self.result.setStyleSheet("color:white;padding:10px;font-size:17px;")
        self.tab3_groupBox1.setFlat(True)

        self.scan_btn_vul.clicked.connect(self.scanner)
        #****************************************************************************
        #                            END-Tab3: Vulnerability                        *
        #****************************************************************************
        # Add tabs to widget

    def selectionchange(self):
        self.cmd=self.cb.currentText() + " " + self.target_ip.text()
        print(self.cmd)
    def scanner(self):
        print("Vulnerability scanning.........")
        o = os.popen(str(self.cmd)).read()
        print(o)
        self.result.insertPlainText(o)
        print("Vulnerability scanning.........DONE")

    def network_scanner(self):
        print("Initiating Network Scanning  .....")
        import nmap
        nm = nmap.PortScanner()
        nm.scan(self.ip_range_start.text()+'/24', arguments='-n -sP -PE')  # -sU -sT -sS -sA
        c1 = 0
        for h in nm.all_hosts():
            # if 'mac' in nm[h]['addresses']:
            self.tableWidget2.insertRow(c1)
            self.tableWidget2.setItem(c1, 1, QTableWidgetItem(str(nm[h]['addresses']['ipv4'])))
            self.tableWidget2.setItem(c1, 2, QTableWidgetItem(str(nm[h]['vendor'])))
            self.tableWidget2.setItem(c1, 3, QTableWidgetItem(str("Unknown")))
            self.tableWidget2.setItem(c1, 4, QTableWidgetItem(str("Unknown")))
            c1 += 1
        print("Network Scanning Completed")

if __name__ =='__main__':
    App = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(App.exec())