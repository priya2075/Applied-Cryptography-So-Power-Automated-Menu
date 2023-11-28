"""

        CLIENT
        FOR ACG ASSIGNMENT 2
        DICS CLASS 1 / 2023
        Date: 24/07/2023
        Coded by Priya d/o Manoharan
        
"""

#-------------------------------------------------------------------------------------- Import stuff
import socket       # tcp protocol
import datetime     # for composing date/time stamp
import sys          # handle system error
import time         # for delay purpose
import hashlib
import hmac
import os
import ssl

# --- Logging and monitoring features 
import logging
# --- NTP synchronization
import ntplib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes <-- currently using fixed IV bytes for DEBUGGING purpose...

# --- TESTING RSA for non-repudiation
from Crypto.Signature import pkcs1_15
from Crypto.Signature import PKCS1_v1_5 as pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


#-------------------------------------------------------------------------------------- Global variables
global host, port
host = '127.0.0.1' # socket.gethostname()
port = 8888
cmd_GET_MENU = b"D:\\02. Tue - IT8084 - Applied Cryptography\\WITHLOGGING\\server\\menu_today.txt"
cmd_END_DAY = b"D:\\02. Tue - IT8084 - Applied Cryptography\\WITHLOGGING\\client\\day_end.csv"
default_menu_file = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGING\client\menu_rcv\menu.csv"
return_file = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGING\client\day_end.csv"

key = b'\xa9\xb5\x01\x87c]\x8e\xd5Ue3\x8dO\x7f\x91\xc8' # 16 byte (fixed) instead of random - due to testing this program
hmac_key = b'abed631a0aadd9dfdc0787f6ae9405b2bfc52f8e50c7e0a7b0d88f2f8bfe81dd255ed98dbe55eb89101f84fad0097c248fc1ab2f4fa6c7dbd6f5454257093b1f' # HMAC key - fixed for testing purposes
iv = b'\xbb(\xbf"\xd8Zx\x8b\xfe.!D\xa4\xf9v\xa7'
MAX_BUFFER_SIZE = 4096


# ------------------------------------------------------------------------------------- SSL / TLS
os.chdir(r'D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGING\client\cKeys') 
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile='client.crt', keyfile='client.key')
context.check_hostname = False #--- This needs to be set to TRUE in a secure and trusted environment.
context.verify_mode = ssl.CERT_NONE #--- this is disabled as it is in a production environment. For secure and trusted environments it needs to be set to REQUIRED


# ------------------------------------------------------------------------------------- KEYS
# Change the working directory to the desired location
os.chdir(r'D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGING\client\cKeys\RSA')
server_public_key = RSA.import_key(open('server_public.pem').read()) # Import the server public key
private_key = RSA.import_key(open('client_private.pem').read()) # Import the client private key
# from Nigel
clear = lambda: os.system('cls')
clear()


#-------------------------------------------------------------------------------------- Welcome message
print(" ")
print("\n\t\t\t      ~ WELCOME ~")
print("\t\t   So Power Automated Menu 2 (SPAM2)")
print("\t\t         ACG ASMT2 | AUG 2023 \n")


#-------------------------------------------------------------------------------------- NTP
def sync_time_with_ntp():
    try:
        # Specify the NTP server you want to use
        ntp_server = 'pool.ntp.org'

        # Create an NTP client and request the time from the server
        client = ntplib.NTPClient()
        response = client.request(ntp_server, version=3)

        # Set the system time with the received NTP time
        ntp_time = datetime.datetime.fromtimestamp(response.tx_time)
        print(f"[*] Synchronized time with NTP server: {ntp_time}")
        logging.info(f"Synchronized time with NTP server: {ntp_time}")
        datetime.datetime.now().replace(year=ntp_time.year, month=ntp_time.month, day=ntp_time.day,
                                        hour=ntp_time.hour, minute=ntp_time.minute, second=ntp_time.second,
                                        microsecond=ntp_time.microsecond)
    except Exception as e:
        print(">> Error synchronizing time with NTP server:", str(e))
        logging.error(f"Error synchronizing time with NTP server: {str(e)}")


# ------------------------------------------------------------------------------------- Client Logging
client_log_folder = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGING\client\client_logs"
os.makedirs(client_log_folder, exist_ok=True)
log_file = os.path.join(client_log_folder, "client_logging.txt")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


#-------------------------------------------------------------------------------------- Receives menu from the server
def receive_menu_from_server():
    try:
        with socket.create_connection((host, port)) as my_socket:
            with context.wrap_socket(my_socket, server_hostname=host) as ssl_socket:
                ssl_socket.sendall(cmd_GET_MENU)
                received_bytes = b""
                while True:
                    data = ssl_socket.recv(4096)
                    if not data:
                        break
                    received_bytes += data

                received_hmac = received_bytes[:32]
                encrypted_data = received_bytes[32:]

                # Verify HMAC
                computed_hmac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()
                if computed_hmac != received_hmac:
                    logging.error("Integrity check failed. Menu data may have been tampered with.")
                else:
                    cipher = AES.new(key, AES.MODE_CBC, encrypted_data[:16])
                    decrypted_menu = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

                    # Specify the folder path
                    folder_path = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGING\client\menu_rcv"

                    # Create the folder if it doesn't exist
                    os.makedirs(folder_path, exist_ok=True)

                    # Generate the filename with the folder path included and timestamp
                    timestamp = datetime.datetime.now().strftime("Menu_Date_%d-%m-%Y_Time_%H-%M-%S.csv")

                    # Generate the filename with the folder path included
                    menu_file = os.path.join(folder_path, timestamp)

                    with open(menu_file, "wb") as out_file:
                        out_file.write(decrypted_menu)

                    print("")
                    print("-" * 68)
                    print("\n>> Menu today RECEIVED from server")
                    print(" - Encryption used: AES and HMAC-SHA256 for integrity check")
                    print(f" - Computed HMAC value: {computed_hmac.hex()}")
                    print(f" - Menu saved as: {menu_file}")
                    print("")
                    print("-" * 68)

                    # Log successful menu retrieval
                    logging.info("Menu today RECEIVED from server")
                    logging.info(" - Encryption used: AES and HMAC-SHA256 for integrity check")
                    logging.info(f" - Computed HMAC value: {computed_hmac.hex()}")
                    logging.info(f" - Menu saved as: {menu_file}")
                    logging.info("-" * 68)

    except Exception as e:
        # Log any exceptions or errors
        logging.error(">> Error while receiving menu from server:", exc_info=True)


#-------------------------------------------------------------------------------------- Send day_end to server
def send_order_to_server():
    try:
        with socket.create_connection((host, port)) as my_socket:
            with context.wrap_socket(my_socket, server_hostname=host) as ssl_socket:
                ssl_socket.sendall(cmd_END_DAY)

                try:
                    with open(return_file, "rb") as out_file:
                        day_closing_data = out_file.read()
                except FileNotFoundError:
                    logging.error("File not found: " + return_file)
                    sys.exit(0)

                iv = b'\xbb(\xbf"\xd8Zx\x8b\xfe.!D\xa4\xf9v\xa7'
                padded_data = pad(day_closing_data, AES.block_size)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(padded_data)

                # Sign the encrypted data
                hash_obj = SHA256.new(day_closing_data)
                signer = pkcs1_15.new(private_key)
                signature = signer.sign(hash_obj)
                encrypted_data_with_signature = encrypted_data + signature

                # Generate HMAC over encrypted_data_with_signature
                hmac_data = hmac.new(hmac_key, encrypted_data_with_signature, hashlib.sha256).digest()
                checksum = hashlib.sha256(encrypted_data_with_signature).digest()

                # Send the IV, encrypted data with signature, and HMAC to the server
                data_to_send = cmd_END_DAY + hmac_data + iv + encrypted_data_with_signature + checksum
                ssl_socket.sendall(data_to_send)

                print("\n>> Sale of the day SENT to server")
                print(" - Command Requested:", cmd_END_DAY)
                print(" - Checksum:", checksum.hex())
                print(f" - Computed HMAC value: {hmac_data.hex()}")
                print(" - IV bytes:", iv)
                print(" - Encrypted Data Length:", len(encrypted_data_with_signature))
                print(" - Original Data Length:", len(day_closing_data))
                print("")
                print("-" * 68)

                # Log successful data transmission
                logging.info("Sale of the day SENT to server")
                logging.info(" - Command Requested: %s", cmd_END_DAY)
                logging.info(" - Checksum: %s", checksum.hex())
                logging.info(f" - Computed HMAC value: {hmac_data.hex()}")
                logging.info(" - IV bytes: %s", iv.hex())
                logging.info(" - Encrypted Data Length: %s", len(encrypted_data_with_signature))
                logging.info(" - Original Data Length: %s", len(day_closing_data))
                logging.info(" ")
                logging.info("-" * 68)

                out_file.close()
                time.sleep(3)
                print("\n>> Exiting SPAM2...")
    except Exception as e:
        # Log any exceptions or errors
        logging.error(">> Error while sending order to server:", exc_info=True)


#-------------------------------------------------------------------------------------- Receive response from server.
def receive_response_from_server():
    try:
        with socket.create_connection((host, port)) as my_socket:
            with context.wrap_socket(my_socket, server_hostname=host) as ssl_socket:
                received_bytes = b""
                while True:
                    data = ssl_socket.recv(4096)
                    if not data:
                        break
                    received_bytes += data

                received_hmac = received_bytes[:32]
                encrypted_data = received_bytes[32:]

                # Verify HMAC
                computed_hmac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()
                if computed_hmac != received_hmac:
                    logging.error("Integrity check failed. Data from server may have been tampered with.")
                    return None
                else:
                    cipher = AES.new(key, AES.MODE_CBC, encrypted_data[:16])
                    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
                    return decrypted_data

    except Exception as e:
        # Log any exceptions or errors
        logging.error(">> Error while receiving response from server:", exc_info=True)
        return None


#-------------------------------------------------------------------------------------- Compare response - called a main()
def compare_response_with_sent_data(sent_data, received_data):
    if sent_data == received_data:
        print("Sent data matches the received data at the server.")
    else:
        print("Sent data does not match the received data at the server. There might be an issue with data transmission or processing.")


#-------------------------------------------------------------------------------------- Call all DEF
def main():
    # Synchronize the client's time with the NTP server
    sync_time_with_ntp()
    receive_menu_from_server()
    send_order_to_server()


# Start the client
if __name__ == "__main__":
    main()
