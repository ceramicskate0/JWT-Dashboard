# JWT-Table - Burp Suite Extension

JWT dashboard extension for Burp.

## 🚀 Features
- A single view for all JWTs (Because lets be honest it needs it) found during your testing that intigrates with all other (as of today) JWT tools found in the Burp extensions market place.
- Makes 1 single view to work with JWTs in the tool vs a dozen little windows.
- Adds a prompt to intigrate with Gen AI to expand on the other tools.

## 📋 Requirements

- **Burp Suite Professional** with or without AI features enabled
- **Montoya API 2025.8** or later
- **Java 17+** runtime environment

## 🛠 Installation

### Method 1: Load the py script
1. Download the repo
2. Open Burp Suite Professional
3. Go to **Extensions** → **Installed** → **Add**
4. Select **Python** as extension type
5. Choose the py file and click **Next**

## 🎯 Usage
- Tool runs passive.
- It will look for JWTs in Proxy history if you turn on extensions in you scanner.
- From there you can stay in the tool or work with others ones through this extension

## 🛡 Security Notice

**This tool is designed for authorized security testing only.**

- ✅ Use only on systems you own or have explicit permission to test
- ✅ Follow responsible disclosure practices
- ✅ Designed for security improvements
- ❌ Not intended for malicious activities

## 📜 License

This extension is designed for authorized security testing and educational purposes. Use responsibly and in accordance with applicable laws and regulations.

Credits:
Readme inspired by https://github.com/PortSwigger/graphql-security-tester
