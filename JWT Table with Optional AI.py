from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
from javax.swing import (JPanel, JScrollPane, JTable, JSplitPane, JTextArea, 
                          JTabbedPane, JCheckBox, JButton, BorderLayout, FlowLayout)
from javax.swing.table import DefaultTableModel, JTableHeader
from javax.swing.event import ListSelectionListener
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from datetime import datetime
import base64
import json
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab, ListSelectionListener, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        # Initialization
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JWT Table with Optional AI")
        
        # State Management
        self.count = 0
        self._seen_jwts = set()
        self._jwt_to_message = {} 
        self._current_message = None 
        
        # Build Interface
        self._initialize_ui_components()
        self._assemble_layout()
        
        # Registration
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        print("JWT extension initialized.")

    def _initialize_ui_components(self):
        """Sets up the individual widgets."""
        self.scope_only_checkbox = JCheckBox("Show Only in-scope items", True)
        self.ai_button = JButton("Copy to Clipboard to Analyze with (Burp) AI", 
                                 actionPerformed=self.handle_ai_request)
        self.ai_button.setEnabled(False)

        self.column_names = ["#", "Found at URL", "Algorithm", "Raw Token"]
        self.column_descriptions = {
            "#": "Sequential order in which the JWT was captured.",
            "Found at URL": "The request URL where this JWT was first discovered.",
            "Raw Token": "The full Base64 encoded JWT string.",
            "Algorithm": "The 'alg' claim from the header (e.g., HS256, RS256).",
            "sub": "Subject: Unique identifier for the user.",
            "iat": "Issued At: The time the JWT was created.",
            "exp": "Expiration: The time the JWT will expire.",
            "iss": "Issuer: The entity that issued the JWT.",
            "aud": "Audience: The intended recipient of the JWT."
        }

        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.getSelectionModel().addListSelectionListener(self)
        self._apply_header_tooltips()

        self.pretty_text = JTextArea()
        self.pretty_text.setEditable(False)
        
        self.request_viewer = self._callbacks.createMessageEditor(self, False)
        self.response_viewer = self._callbacks.createMessageEditor(self, False)

    def _assemble_layout(self):
        """Connects the components into the final layout."""
        top_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        top_bar.add(self.scope_only_checkbox)
        top_bar.add(self.ai_button)

        tab_view = JTabbedPane()
        tab_view.addTab("Request", self.request_viewer.getComponent())
        tab_view.addTab("Response", self.response_viewer.getComponent())

        lower_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.pretty_text), tab_view)
        lower_split.setDividerLocation(450)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), lower_split)
        main_split.setDividerLocation(300)

        self.root_panel = JPanel(BorderLayout())
        self.root_panel.add(top_bar, BorderLayout.NORTH)
        self.root_panel.add(main_split, BorderLayout.CENTER)

    def _apply_header_tooltips(self):
        class TooltipHeader(JTableHeader):
            def __init__(self, table, tips):
                JTableHeader.__init__(self, table.getColumnModel())
                self.tips = tips
            def getToolTipText(self, event):
                idx = self.columnAtPoint(event.getPoint())
                if idx != -1:
                    label = self.getTable().getColumnName(idx)
                    return self.tips.get(label, "Claim: " + label)
                return None
        self.table.setTableHeader(TooltipHeader(self.table, self.column_descriptions))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We only care about Proxy traffic
        if toolFlag != self._callbacks.TOOL_PROXY:
            return

        req_info = self._helpers.analyzeRequest(messageInfo)
        target_url = req_info.getUrl()

        # Scope Check
        if self.scope_only_checkbox.isSelected() and not self._callbacks.isInScope(target_url):
            return

        # Scan for JWT patterns in request/response
        full_content = self._helpers.bytesToString(messageInfo.getRequest())
        if messageInfo.getResponse():
            full_content += " " + self._helpers.bytesToString(messageInfo.getResponse())

        jwt_pattern = r'ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]*'
        found_tokens = re.findall(jwt_pattern, full_content)

        for token in found_tokens:
            if token not in self._seen_jwts:
                self._seen_jwts.add(token)
                
                # Extract alg for table
                try:
                    header_json = self._parse_token_segment(token.split('.')[0])
                    algorithm = json.loads(header_json).get("alg", "Unknown")
                except:
                    algorithm = "Error"

                self.count += 1
                self._jwt_to_message[token] = messageInfo
                self.table_model.addRow([self.count, target_url.toString(), algorithm, token])

    def _parse_token_segment(self, segment):
        rem = len(segment) % 4
        if rem > 0: segment += "=" * (4 - rem)
        return base64.urlsafe_b64decode(segment.encode('ascii')).decode('utf-8', 'ignore')

    def valueChanged(self, event):
        if event.getValueIsAdjusting(): return
        
        idx = self.table.getSelectedRow()
        if idx != -1:
            self.ai_button.setEnabled(True)
            m_idx = self.table.convertRowIndexToModel(idx)
            raw_jwt = self.table_model.getValueAt(m_idx, 3) # Raw Token column
            
            if raw_jwt in self._jwt_to_message:
                msg_data = self._jwt_to_message[raw_jwt]
                self._current_message = msg_data
                self.request_viewer.setMessage(msg_data.getRequest(), True)
                self.response_viewer.setMessage(msg_data.getResponse() or [], False)
                
                # Populate Pretty View
                try:
                    bits = raw_jwt.split('.')
                    h = json.dumps(json.loads(self._parse_token_segment(bits[0])), indent=4)
                    p = json.dumps(json.loads(self._parse_token_segment(bits[1])), indent=4)
                    self.pretty_text.setText("--- HEADER ---\n%s\n\n--- PAYLOAD ---\n%s" % (h, p))
                    self.pretty_text.setCaretPosition(0)
                except:
                    self.pretty_text.setText("Decoding error.")
        else:
            self.ai_button.setEnabled(False)

    def handle_ai_request(self, event):
        if not self._current_message: return

        row_view = self.table.getSelectedRow()
        row_model = self.table.convertRowIndexToModel(row_view)
        jwt_val = self.table_model.getValueAt(row_model, 3)
        req_val = self._helpers.bytesToString(self._current_message.getRequest())

        prompt = (
            "SYSTEM: You are a senior web security researcher and JWT implementation expert.\n"
            "USER: Please perform a deep security analysis on the following JWT and its associated HTTP request.\n"
            "Objectives:\n"
            "Header Analysis: Check for insecure alg values (e.g., none), algorithm confusion vulnerabilities (RS256 vs HS256), and potentially malicious kid or jku parameters.\n"
            "Payload/Claim Audit: Inspect for sensitive data leakage, missing or excessively long exp (expiration) times, and lack of iat (issued at) or nbf (not before) claims.\n"
            "Request Context: Analyze how the JWT is transmitted (e.g., Header vs Cookie). Check for missing HttpOnly or Secure flags if it's a cookie.\n"
            "Attack Vectors: Suggest specific test cases for algorithm confusion, weak secret brute-forcing, or signature bypass.\n"
            "Data:\n"
            "--- TARGET JWT ---\n%s\n\n"
            "--- FULL HTTP REQUEST ---\n%s"
        ) % (jwt_val, req_val)

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(prompt), None)
        print("AI prompt buffered to clipboard.")

    # ITab implementation
    def getTabCaption(self): return "JWT AI"
    def getUiComponent(self): return self.root_panel

    # IMessageEditorController implementation
    def getHttpService(self): return self._current_message.getHttpService()
    def getRequest(self): return self._current_message.getRequest()
    def getResponse(self): return self._current_message.getResponse()
