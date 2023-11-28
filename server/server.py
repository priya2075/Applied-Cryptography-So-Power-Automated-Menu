"""

        SERVER
        FOR ACG GROUP ASSIGNMENT 2
        DICS CLASS 1 / 2023
        Date: 24/07/2023
        Coded by: Priya d/o Manoharan

"""

#-------------------------------------------------------------------------------------- Import stuff
import socket       # tcp protocol
import datetime     # for composing date/time stamp
import sys          # handle system error
import traceback    # for print_exc function
import time         # for delay purpose
import hashlib
import hmac
import os
import select
import ssl

# --- Logging and monitoring features 
import logging
# --- NTP synchronization
import ntplib

from threading import Thread
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- TESTING RSA for non-repudiation
from Crypto.Signature import PKCS1_v1_5 as pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


#-------------------------------------------------------------------------------------- Global variables
host = '0.0.0.0' # socket.gethostname()
port = 8888
cmd_GET_MENU = b"D:\\02. Tue - IT8084 - Applied Cryptography\\WITHLOGGINGrrr\\server\\menu_today.txt"
cmd_END_DAY = b"D:\\02. Tue - IT8084 - Applied Cryptography\\WITHLOGGINGrrr\\client\\day_end.csv"
default_menu = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\menu_today.txt"
default_save_base = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\Result\day_end.csv"

key = b'\xa9\xb5\x01\x87c]\x8e\xd5Ue3\x8dO\x7f\x91\xc8' # 16 byte (fixed) instead of random - due to testing this program
hmac_key = b'abed631a0aadd9dfdc0787f6ae9405b2bfc52f8e50c7e0a7b0d88f2f8bfe81dd255ed98dbe55eb89101f84fad0097c248fc1ab2f4fa6c7dbd6f5454257093b1f' # HMAC key - fixed for testing purposes
fixed_iv = b'\xbb(\xbf"\xd8Zx\x8b\xfe.!D\xa4\xf9v\xa7'
iv = fixed_iv
MAX_BUFFER_SIZE = 4096
cipher = AES.new(key, AES.MODE_CBC, iv) 

# ------------------------------------------------------------------------------------- KEYS
# Change the working directory to the desired location
os.chdir(r'D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\sKeys\RSA')
client_public_key = RSA.import_key(open('client_public.pem').read()) # Import the client's public key
private_key = RSA.import_key(open('server_private.pem').read()) # Import the server's private key
server_public_key = RSA.import_key(open('server_public.pem').read()) 
# from Nigel
clear = lambda: os.system('cls')
clear()


# ------------------------------------------------------------------------------------- Server Logging
server_log_folder = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\server_logs"
os.makedirs(server_log_folder, exist_ok=True)
log_file = os.path.join(server_log_folder, "server_logging.txt")


#-------------------------------------------------------------------------------------- Process connection with SSL/TLS
def process_connection(conn, ip_addr, MAX_BUFFER_SIZE, connections_complete):
    # Configure logging for this function
    log_filename = f"process_connection_{ip_addr.replace(':', '_')}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = None
    received_data = b''

    while net_bytes != b'':
        if blk_count == 0:  # 1st block
            try:
                usr_cmd = net_bytes.decode().rstrip()
                print(f">> Received user command: {usr_cmd}")
                logging.info(f"Received user command: {usr_cmd}")
            except UnicodeDecodeError:
                print(">> Error decoding user command: Invalid encoding")
                logging.error(">> Error decoding user command: Invalid encoding")
                break

            if cmd_GET_MENU.decode() == usr_cmd:
                try:
                    src_file = open(default_menu, "rb")
                    menu_data = src_file.read()

                    # Generate a random IV for each connection
                    iv = get_random_bytes(AES.block_size)

                    # Encrypt the menu data using AES
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    encrypted_menu = cipher.encrypt(pad(menu_data, AES.block_size))

                    # Compute a hash of the menu data for integrity check
                    menu_hash = hashlib.sha256(menu_data).digest()

                    # Append the menu hash and IV to the encrypted menu data
                    encrypted_menu_with_hash = menu_hash + iv + encrypted_menu

                    # Generate HMAC of the encrypted menu data
                    hmac_menu = hmac.new(hmac_key, encrypted_menu_with_hash, hashlib.sha256).digest()

                    # Append the HMAC to the encrypted menu data
                    encrypted_menu_with_hmac = hmac_menu + encrypted_menu_with_hash

                    conn.sendall(encrypted_menu_with_hmac)
                    src_file.close()
                    print("\n>> Sent menu data encrypted using AES, integrity protected, and HMAC appended.")
                    print(f">> Server HMAC value: {hmac_menu.hex()}")
                    logging.info("Sent menu data encrypted using AES, integrity protected, and HMAC appended.")
                    logging.info(f"Server HMAC value: {hmac_menu.hex()}")
                    #print(f">> menu_hash value: {menu_hash.hex()}")
                    #print(f">> encrypted_menu_with_hash value: {encrypted_menu_with_hash.hex()}")
                    return
                except FileNotFoundError:
                    print(">> File not found:", default_menu)
                    logging.error(f">> File not found: {default_menu}")
                    sys.exit(0)

            elif cmd_END_DAY.decode().strip() == usr_cmd:
                # Specify the folder path
                folder_path = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\Result"

                # Create the folder if it doesn't exist
                os.makedirs(folder_path, exist_ok=True)

                # Generate the filename with the folder path included
                filename = os.path.join(
                    folder_path,
                    default_save_base + " - " + ip_addr.replace(":", "_") + " - " + datetime.datetime.now().strftime("Date_%d-%m-%Y_Time_%H-%M-%S")
                )
                # Open the file in the specified folder for writing
                dest_file = open(filename, "wb")
                dest_file.write(net_bytes[len(cmd_END_DAY):])
                blk_count = blk_count + 1
                print("\n>> Saving encrypted file as:\n- ", filename)
                logging.info("Saving encrypted file as " + filename)
                time.sleep(1)

                # Verify the signature
                encrypted_data = net_bytes[len(cmd_END_DAY):-256]
                signature = net_bytes[-256:]
                encrypted_data = encrypted_data[:-256]
                hash_obj = SHA256.new(encrypted_data)
                verifier = pkcs1_15.new(client_public_key)
                try:
                    #print(">> Encrypted data:", encrypted_data)
                    print(">> Signature:", signature)
                    print(">> Hash object:", hash_obj.hexdigest())
                    #logging.info("Encrypted data: " + encrypted_data.hex())
                    logging.info("Signature: " + signature.hex())
                    logging.info("Hash object: " + hash_obj.hexdigest())
                    verifier.verify(hash_obj, signature)
                    print(">> Signature verification successful. Data is authentic.")
                    logging.info("Signature verification successful. Data is authentic.")
                except (ValueError, TypeError):
                    print(">> Warning: !! Signature verification failed...")
                    logging.warning(">> Signature verification failed. Data may have been tampered with.")
               
        else:
            if dest_file:
                dest_file.write(net_bytes)
                received_data += net_bytes
        net_bytes = conn.recv(MAX_BUFFER_SIZE)

    if dest_file:
        dest_file.close()
        connections_complete[ip_addr][0] = True
        encrypted_data = received_data[len(cmd_END_DAY):]
        process_end_day_data(encrypted_data, ip_addr)  


#-------------------------------------------------------------------------------------- Vefify HMAC and decrypt data
def verify_and_decrypt_data(encrypted_data, client_public_key):
    try:
        # Verify HMAC
        received_hmac = encrypted_data[:32]
        encrypted_data_with_signature = encrypted_data[32:]
        computed_hmac = hmac.new(hmac_key, encrypted_data_with_signature, hashlib.sha256).digest()
        received_checksum = encrypted_data_with_signature[-32:]
        computed_checksum = hashlib.sha256(encrypted_data_with_signature[:-32]).digest()

        # Print intermediate values for debugging
        print("-- Received Checksum from Client:", received_checksum.hex())
        print("-- Received HMAC from Client:", received_hmac.hex())
        logging.info("-- Received Checksum from Client: %s", received_checksum.hex())
        logging.info("-- Received HMAC from Client: %s", received_hmac.hex())
        print("--> Computed Checksum within verify_and_decrypt_data:", computed_checksum.hex())
        print("--> Computed HMAC within verify_and_decrypt_data:", computed_hmac.hex())
        logging.info("--> Computed Checksum within verify_and_decrypt_data: %s", computed_checksum.hex())
        logging.info("--> Computed HMAC within verify_and_decrypt_data: %s", computed_hmac.hex())

        if hmac.compare_digest(computed_hmac, received_hmac):
            # HMAC verification successful
            # Continue with decryption since HMAC and checksum verification passed
            # Decrypt the data using AES-CBC mode with padding
            received_iv = encrypted_data[32: 32 + AES.block_size]  # Extract the received IV
            encrypted_data = encrypted_data[32 + AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, received_iv)

            # Perform length check
            expected_length = len(received_hmac) + AES.block_size + len(signature)
            print(f"Expected length: {expected_length}")
            print(f"Actual length: {len(encrypted_data_with_signature)}")
            if len(encrypted_data_with_signature) != expected_length:
                raise ValueError("Incorrect length of encrypted_data_with_signature.")

            # Verify byte sequence order
            received_hmac_check = encrypted_data_with_signature[:len(received_hmac)]
            signature_check = encrypted_data_with_signature[-len(signature):]
            print(f"Received HMAC Check: {received_hmac_check.hex()}")
            print(f"Expected HMAC: {received_hmac.hex()}")
            print(f"Signature Check: {signature_check.hex()}")
            print(f"Expected Signature: {signature.hex()}")
            if received_hmac_check != received_hmac or signature_check != signature:
                raise ValueError("Incorrect byte sequence order in encrypted_data_with_signature.")

            # Perform padding check (if applicable)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            print(">> Decrypted data within verify_and_decrypt_data:", decrypted_data)  # Debugging print
            logging.info("Decrypted data within verify_and_decrypt_data: %s", decrypted_data)

            # Split the decrypted data into the original data and the signature
            original_data = decrypted_data[:-256]
            signature = decrypted_data[-256:]

            # Verify the signature using the client's public key
            verifier = pkcs1_15.new(client_public_key)
            digest = SHA256.new(original_data)
            if verifier.verify(digest, signature):
                print(">> Verifying signature... Signature verification successful. Data is authentic.")
                logging.info("Signature verification successful. Data is authentic.")
                return original_data
            else:
                print(">> Signature verification failed. Data may have been tampered with.")
                logging.warning("Signature verification failed. Data may have been tampered with.")
                return None
        else:
            # Debugging print
            print(">> Warning: !! Integrity check failed. Data may have been tampered with.\n")
            logging.warning(">> Integrity check failed. Data may have been tampered with.")
            # Logging messages with proper formatting
            logging.info("Received HMAC within verify_and_decrypt_data: %s", received_hmac.hex())
            logging.info("Computed HMAC within verify_and_decrypt_data: %s", computed_hmac.hex())
            return None

    except Exception as e:
        print(">> Error during decryption:", str(e))
        logging.error(">> Error during decryption:", str(e))
        return None




        
#-------------------------------------------------------------------------------------- Process day_end.csv decryption
def process_end_day_data(data, ip_addr):
    try:
        # Find the index where the signature starts
        signature_index = len(data) - 256
        signature = data[signature_index:]
        encrypted_data = data[len(cmd_END_DAY):signature_index]

        print(">> Encrypted data before decryption:", encrypted_data)  # Debugging print
        
        # Verify the signature
        hash_obj = SHA256.new(encrypted_data)
        verifier = pkcs1_15.new(client_public_key)
        try:
            print("")
            print("\n[+] Decryption Section:")
            print("-"*68)
            print(">> Verifying signature...")
            logging.info("Verifying signature...")
            verifier.verify(hash_obj, signature)
            print(">> Signature verification successful. Data is authentic.")
            logging.info("Signature verification successful. Data is authentic.")
        except (ValueError, TypeError):
            print(">> Warning: !! Due to signature verification failure, data may have been tampered with.")
            logging.warning(">> Warning: !! Due to signature verification failure, data may have been tampered with.")

        # Decrypt the data
        print("\n[+] Before verify_and_decrypt_data() function call")
        print("-"*68)
        decrypted_data = verify_and_decrypt_data(encrypted_data, client_public_key)
        print("[+] After verify_and_decrypt_data() function call")
        print("-"*68)

        if decrypted_data is not None:
            print(">> Decrypted data within process_end_day_data:", decrypted_data) # Print decrypted data to check if it is correct

            # Save the decrypted data to a file
            decrypted_folder_path = r"D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\Decrypted"
            os.makedirs(decrypted_folder_path, exist_ok=True)
            
            # Define a file_prefix for the filename
            file_prefix = "decrypted"
            decrypted_filename = os.path.join(
                decrypted_folder_path,
                file_prefix + " - " + ip_addr.replace(":", "_") + " - " + datetime.datetime.now().strftime("D_%d-%m-%Y_T_%H-%M-%S") + ".csv"
            )
            with open(decrypted_filename, "wb") as decrypted_dest_file:
                decrypted_dest_file.write(decrypted_data)

            print("\n>> Decrypted data saved as\n- ", decrypted_filename)
            logging.info("Decrypted data saved as " + decrypted_filename)
            
        else:
            print(">> Decryption or verification failed. Data may have been tampered with.")
            logging.warning(">> Decryption or verification failed. Data may have been tampered with.")
    except Exception as e:
        print(">> Error while processing end-of-day data:", str(e))
        logging.error(f">> Error while processing end-of-day data: {str(e)}")



#-------------------------------------------------------------------------------------- Client thread with SSL/TLS
def client_thread(conn, ip, port, MAX_BUFFER_SIZE, connections_complete):
    # Configure logging for this function
    log_filename = f"client_thread_{ip.replace(':', '_')}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        # Change the working directory to the client folder
        os.chdir(r'D:\02. Tue - IT8084 - Applied Cryptography\WITHLOGGINGrrr\server\sKeys')

        # Establish SSL/TLS connection
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='acg.pem', keyfile='private.key')

        # Wrap the connection socket with SSL/TLS
        ssl_socket = context.wrap_socket(conn, server_side=True)

        # Get the TLS version and cipher suite
        tls_version = ssl_socket.version()
        cipher_suite = ssl_socket.cipher()

        print(f">> TLS Version: {tls_version}")
        print(f">> Cipher Suite: {cipher_suite}")
        logging.info(f"TLS Version: {tls_version}")
        logging.info(f"Cipher Suite: {cipher_suite}")

        process_connection(ssl_socket, ip, MAX_BUFFER_SIZE, connections_complete)

    except Exception as e:
        traceback.print_exc()
        print(">> Error occurred:", str(e))
        logging.error(f">> Error occurred: {str(e)}")
    finally:
        if 'ssl_socket' in locals():
            ssl_socket.close()
            print(" ")
            print("-" * 68)
            print(f'[x] Connection {ip}:{port} closed.')
            print("=" * 68)
            print(" ")
            logging.info(f'[x] Connection {ip}:{port} closed.')
            logging.info("=" * 68)


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


#-------------------------------------------------------------------------------------- Start the server
def start_server():
    global host, port
    sync_time_with_ntp()
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('\n>> Socket created')
    logging.info('Socket created')

    try:
        soc.bind((host, port))
        print('>> Socket bind complete')
        logging.info('Socket bind complete')
    except socket.error as msg:
        print('>> Bind failed. Error:', str(sys.exc_info()))
        logging.error(f'>> Bind failed. Error: {str(sys.exc_info())}')
        print(msg.with_traceback())
        sys.exit()

    soc.listen(10)
    print(f">> Socket is now listening on {host} at Port: {port}")
    logging.info(f"Socket is now listening on {host} at Port: {port}")
    print("-" * 68)
    print(" ")
    logging.info("-" * 68)
    logging.info(" ")

    # Use select to listen for new connections and check for completion
    inputs = [soc]
    running = True
    completed_connections = 0
    connections_complete = {}  # Dictionary to track completion of connections

    while running:
        readable, _, _ = select.select(inputs, [], [], 0.1)

        for sock in readable:
            if sock == soc:
                conn, addr = soc.accept()
                ip, port = str(addr[0]), str(addr[1])
                print(f'\n[*] Accepting connection from {ip}:{port}')
                print("-" * 68)
                logging.info(f'[*] Accepting connection from {ip}:{port} - IP: {ip} - Port: {port}')
                logging.info("-" * 68)
                Thread(target=client_thread, args=(conn, ip, port, 4096, connections_complete)).start()
                completed_connections += 1
                connections_complete[ip] = [False]

                if completed_connections == 2:  # Change the number as needed
                    running = False
                    break
    soc.close()


#-------------------------------------------------------------------------------------- Starting server + message
print("")
print("-" * 68)
print(f"[*] Starting up server on {host} at Port: {port}")
print("-" * 68)


# Add the logging configuration here
logging.basicConfig(
    filename='server.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Start the server
start_server()
