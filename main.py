"""
Telegram File Drive by 'nloginov'

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""

# Imports
import os
import json
import secrets
import string
import base64
import asyncio
from datetime import datetime
from math import log

from telethon import TelegramClient, events
from telethon.tl import functions, types

# Function to encode data to Base64
def base64_encode(data):
    return base64.b64encode(data)

# Function to decode Base64 encoded data
def base64_decode(encoded_data):
    return base64.b64decode(encoded_data)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Telethon login info, you can get this at my.telegram.org
api_id = 12345678
api_hash = ''
client = TelegramClient('anon', api_id, api_hash)

# Your channel
invite_link = 'https://t.me/+-2cdcBh7RacdYFCe' # Invite link to your private channel

# Global variable to store the entity
entity = None

# Folder configuration
folder_name = 'drive' # This is the folder where all your files are handled, this can be 'C:\Users\User\Downloads\My Files' or just 'MyFiles'
download_name = 'downloads' # This is the folder to which all the files will be downloaded, same like with the one above
meta_file = 'metadata.json' # This is where information about your files is being stored

# Queue kept in memory to see what gets uploaded and what doesn't
upload_queue = []

# Random string
def generate_random_string(length = 16):
    # Define the set of characters to choose from
    characters = string.ascii_letters + string.digits
    
    # Generate a random string of specified length
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

# Format bytes
def format_size(size_bytes):
    """
    Convert size in bytes to human-readable format.
    """
    if size_bytes == 0:
        return "0 B"
    # Define the units and their respective step sizes
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    step = 1024
    # Calculate the exponent for the appropriate unit
    exponent = min(int(log(size_bytes, step)), len(units) - 1)
    # Calculate the value in the chosen unit
    size = size_bytes / pow(step, exponent)
    # Format the size with two decimal places
    formatted_size = '{:.2f} {}'.format(size, units[exponent])
    return formatted_size

# This is for storing info about our files
class metadata_handler:
    def __init__(self, filename):
        self.filename = filename

    def write(self, files):
        metadata = {'files': files}
        with open(self.filename, 'w') as f:
            json.dump(metadata, f, indent=4)

    def parse(self):
        try:
            with open(self.filename, 'r') as f:
                metadata = json.load(f)
                if 'files' in metadata:
                    return metadata['files']
                else:
                    return None
        except FileNotFoundError:
            return None

# Open handler, should always be running
metadata = metadata_handler(meta_file)

# Encryption key, used later in the code
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )

    return kdf.derive(password.encode())

# Download a file by ID
async def download(file_uid):
    global entity
    
    if not os.path.exists(download_name) or not os.path.isdir(download_name):
        print("Download folder does not exist or is not a directory.")

    parsed_files = metadata.parse()
    if parsed_files is None:
        print("No metadata found.")

        return

    if file_uid in parsed_files:
        async for message in client.iter_messages(entity):
            if message.file:
                if message.file.name == file_uid:
                    # Dummy
                    actual_path = ""
                    
                    # Generate the initial filename
                    init_path = parsed_files[file_uid]["path"] # Initial path, used as support for folders
                    init_path = os.path.split(init_path)[0][len(f"{folder_name}\\"):] # Modify it so that there are no issues

                    base_name = parsed_files[file_uid]["name"] # File name when the file got uploaded
                    extension = parsed_files[file_uid]["extension"] # File extension when the file got uploaded
                    
                    if extension:
                        actual_path = f"{download_name}/{init_path}/{base_name}{extension}"
                    else:
                        actual_path = f"{download_name}/{init_path}/{base_name}"

                    # Check if the file exists
                    counter = 1

                    while os.path.exists(actual_path):
                        # If the file exists, generate a new filename with an incremented counter
                        counter += 1

                        if extension:
                            actual_path = f"{download_name}/{init_path}/{base_name} #{counter}{extension}"
                        else:
                            actual_path = f"{download_name}/{init_path}/{base_name} #{counter}"

                    def callback(current, total):
                        print('Downloaded', current, 'out of', total,
                              'bytes: {:.2%}'.format(current / total))

                    await client.download_media(message, file=actual_path, progress_callback=callback)
                    
                    # Decryption
                    password = parsed_files[file_uid]["secret"]
                    if password:
                        with open(actual_path, 'rb') as f:
                            salt = f.read(16)
                            iv = f.read(16)
                            encrypted_data_base64 = f.read()
                        
                        # Decode Base64
                        encrypted_data = base64_decode(encrypted_data_base64)
                        
                        # Decode File
                        key = generate_key(password, salt)
                        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
                        with open(actual_path, 'wb') as f:
                            f.write(decrypted_data)
    else:
        print("File with this identificator is not valid.")

        return

# Uploads everything in the upload queue
async def upload():
    global entity

    for file in upload_queue:
        # Very important, otherwise we will get shit on by errors
        if not os.path.exists(file[0]):
            upload_queue.remove(file)

            continue

        # Encryption
        with open(file[0], 'rb') as f:
            data = f.read()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(file[2]), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Encode Base64
        encrypted_data_base64 = base64_encode(encrypted_data)

        with open(file[0], 'wb') as f:
            f.write(file[3])
            f.write(iv)
            f.write(encrypted_data_base64)

        # Progress
        async def callback(current, total):
            fmt = 'bytes: {:.2%}'.format(current / total)
            print(file[0], ': uploaded', current, 'out of', total, fmt)
        
        # Attributes, used for new filename
        attributes = [types.DocumentAttributeFilename(file[1])]

        # Use the input_file method to specify the file
        input_file = await client.upload_file(file[0], progress_callback=callback)
        
        # Send the file using InputMediaUploadedDocument
        await client.send_file(entity, input_file, attributes=attributes, force_document=True)
        
        # Clean up the trash
        upload_queue.remove(file) # Remove it from the list because it has already been uploaded
        os.remove(file[0]) # Remove the file from the local device, since we keep it in the cloud

# This function compares the files on your system against the files in the metadata, and checks if synchronization is needed
# Also it uploads new files, hehexd
async def validate_drive():
    global entity

    if not os.path.exists(folder_name) or not os.path.isdir(folder_name):
        print("Synchronization folder does not exist or is not a directory.")
    
    # Parsed files    
    parsed_files = metadata.parse()
    if parsed_files is None:
        parsed_files = {}  
    
    # Placeholder for new files
    metadata_new = parsed_files

    for root, dirs, files in os.walk(folder_name):
        for file in files:
            file_path = os.path.join(root, file)
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                continue # Skip if the file is empty, since Telegram doesn't allow those
            
            # Some weird logic that fixes issues related to files w/o extensions
            file_id = os.path.splitext(file)

            # Add in upload queue
            rnd_str = generate_random_string(14) # Random encoded file ID
            
            # Make it truly unique, although it eats performance and you can avoid this by a longer IDs
            while rnd_str in parsed_files:
                rnd_str = generate_random_string()
            
            # Decryption password, we need encryption just for those files not to be viewable in any way on Telegram
            password = generate_random_string(12)
            salt = os.urandom(16) # Also needed and must be the same, that's why I use a variable

            # Add
            metadata_new[rnd_str] = {'size': file_size, 'secret': password, 'path': file_path, 'name': file_id[0], 'extension': file_id[1], 'uploaded': datetime.now().isoformat()}
            
            upload_queue.append([file_path, rnd_str, generate_key(password, salt), salt])


    metadata.write(metadata_new)
    
    await upload()

# Validate drive on command
@client.on(events.NewMessage(outgoing=True, pattern='/sync'))
async def handler(event):
    try:
        await validate_drive()
    except Exception as e:
        print(f"Couldn't synchronize files properly: {e}")
        return 

    message = await event.respond(
        '**SYNCHRONIZED** the drive successfully!',
        link_preview=False
    )

# Upload file, kind of a ghetto solution to be honest
@client.on(events.NewMessage(outgoing=True, pattern='/upload'))
async def handler(event):
    if event.document:
        ## Find the DocumentAttributeFilename object
        file_name_attr = next((x for x in event.media.document.attributes if isinstance(x, types.DocumentAttributeFilename)), None)

        if file_name_attr:
            # Extract the file name
            file_name = file_name_attr.file_name
            
            message = await event.respond(
                f'Starting upload of: **{file_name}**',
                link_preview=False
            )

            # Download the file
            await event.download_media(file=os.path.join(folder_name, file_name))

            # Call synchronization
            try:
                await validate_drive(event)
            except Exception as e:
                print(f"An error occurred while synchronizing the files: {e}")
                return 
            
            await client.edit_message(event.chat_id, message.id,
                f'**SUCCESS**, {file_name} has been uploaded to the cloud!',
                link_preview=False
            )
        else:
            message = await event.respond(
                'Sorry, but there are issues with parsing this document...',
                link_preview=False
            )

# Download file by UID
@client.on(events.NewMessage(outgoing=True, pattern=r'/download (.+)'))
async def handler(event):
    file_uid = event.pattern_match.group(1)

    if not file_uid in metadata.parse():
        print("File has not been found.")
    else:
        message = await event.respond(
            f'Starting download of: **{file_uid}**',
            link_preview=False
        )
        
        # Start download
        await download(file_uid)

        await client.edit_message(event.chat_id, message.id,
            f'**DOWNLOADED** {file_uid} from the drive successfully!',
            link_preview=False
        )

# Function to generate the list of file details
def generate_embed_list():
    embed_list = []
    parsed_files = metadata.parse()

    for file in parsed_files:
            file_name = parsed_files[file]['name']
            file_extension = parsed_files[file]['extension']
            file_size = parsed_files[file]['size']
            file_size_fmt = format_size(file_size)  # Convert bytes to a readable format
            file_upload_date = parsed_files[file]['uploaded']
            modified_date = datetime.strptime(file_upload_date, '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d %H:%M:%S')
            
            # Create the embed for each file
            embed = f"**UID:** {file}\n" \
                    f"**File Name:** {file_name}\n" \
                    f"**Extension:** {file_extension}\n" \
                    f"**Size:** {file_size_fmt}\n" \
                    f"**Upload Date:** {modified_date}\n\n"
            
            embed_list.append(embed)
    return embed_list

@client.on(events.NewMessage(outgoing=True, pattern='/list'))
async def handler(event):
    embed_list = generate_embed_list()
    
    # Join all embeds into a single message
    embed_message = ''.join(embed_list)
    
    # Send the message
    await event.respond(embed_message)

# Ugly looking main function
async def main():
    global entity
    await client.start()
    entity = await client.get_entity(invite_link)
    await client.run_until_disconnected()

if __name__ == '__main__':
    asyncio.run(main())
