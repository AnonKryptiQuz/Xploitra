# Xploitra: Reverse Shell Payload Generator

**Xploitra** is a versatile and powerful reverse shell payload generator tool designed for educational and security testing purposes. It allows users to generate reverse shell payloads with customizable options, leveraging various obfuscation techniques and session management. This tool is highly adaptable for simulating real-world attack scenarios and testing the security posture of systems.

## **Features**

- **Payload Generation**: Creates obfuscated reverse shell payloads for Windows platforms.
- **Cross-Platform**: The tool can generate the payload on any OS.
- **Session Management**: Allows handling multiple reverse shell sessions concurrently.
- **Obfuscation**: Uses randomized encoding and string manipulation techniques to bypass basic detection mechanisms.
- **Payload Customization**: Modify IP, port, and payload execution commands for tailored payloads.
- **Base64 Encoding**: Encodes the payload for easy delivery through secure channels.

## **Prerequisites**

- **Python 3.7+**
- **tqdm** (Progress bar functionality)

## **Installation**

1. **Clone the repository:**

   ```bash
   git clone https://github.com/AnonKryptiQuz/Xploitra.git
   cd Xploitra
   ```

2. **Install the required packages:**

   ```bash
   pip install -r requirements.txt
   ```

   **Ensure `requirements.txt` contains:**

   ```text
   tqdm==4.64.1
   ```

## **Usage**

1. **Run the tool:**

   ```bash
   python Xploitra.py -l <LOCAL_IP> -p <PORT> [-n ngrok]
   ```

2. **Follow the prompts to configure and generate your reverse shell payload.**

3. **After generation, the payload will be saved as a `.bat` file, which is compatible with Windows systems.**

## **Disclaimer**

- **Educational Purposes Only**: Xploitra is intended for educational and research use. The tool should not be used for illegal or malicious activities. It is the user’s responsibility to ensure compliance with local laws and regulations.

## **Author**

**Created by:** [AnonKryptiQuz](https://AnonKryptiQuz.github.io/)
