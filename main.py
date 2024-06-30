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
import aiofiles
import asyncio
import zlib
import threading
import hashlib
from datetime import datetime
from math import log
import time
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from telethon import TelegramClient, Button, events
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
api_id = 28693544
api_hash = '3edef0ce8ff5234a97a372fda9004f'
client = TelegramClient('anon', api_id, api_hash)

# Your channel
invite_link = 'https://t.me/+-5sdcRe8RdawYTGi' # Invite link to your private channel

# Global variable to store the entity
entity = None
metadata = None

# Folder configuration
folder_name = 'drive' # This is the folder where all your files are handled
download_name = 'downloads' # This is the folder to which all the files will be downloaded
meta_file = 'metadata.json' # This is where information about your files is being stored

# Constants
CHUNK_SIZE = 20 * 1024 * 1024  # 20MB
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# Initialize
async def initialize_folders_and_files():
    # Create the main folder if it doesn't exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Created main folder: {folder_name}")

    # Create the downloads folder if it doesn't exist
    if not os.path.exists(download_name):
        os.makedirs(download_name)
        print(f"Created downloads folder: {download_name}")

    # Create the metadata file if it doesn't exist
    if not os.path.exists(meta_file):
        with open(meta_file, 'w') as f:
            json.dump({'files': {}}, f)
        print(f"Created metadata file: {meta_file}")

# Random string
def generate_random_string(length = 16):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

# Format bytes
def format_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    step = 1024
    exponent = min(int(log(size_bytes, step)), len(units) - 1)
    size = size_bytes / pow(step, exponent)
    return '{:.2f} {}'.format(size, units[exponent])

def compress_data(data):
    return zlib.compress(data)

def decompress_data(data):
    return zlib.decompress(data)

# Improved metadata handler
class MetadataHandler:
    def __init__(self, filename):
        self.filename = filename
        self.metadata = self.load()

    def load(self):
        try:
            with open(self.filename, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return {'files': {item['uid']: item for item in data}}
                elif isinstance(data, dict) and 'files' in data:
                    return data
                else:
                    return {'files': {}}
        except FileNotFoundError:
            return {'files': {}}

    def save(self):
        with open(self.filename, 'w') as f:
            json.dump(self.metadata, f, indent=4)

    def get_files(self):
        return self.metadata['files']

    async def update_file(self, file_id, file_info):
        self.metadata['files'][file_id] = file_info
        self.save()

    async def remove_file(self, file_id):
        if file_id in self.metadata['files']:
            del self.metadata['files'][file_id]
            self.save()

# Encryption key
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    return kdf.derive(password.encode())

# File system event handler
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, loop, sync_function):
        self.loop = loop
        self.sync_function = sync_function
        self.debounce_timer = None

    def on_any_event(self, event):
        if self.debounce_timer is not None:
            self.debounce_timer.cancel()
        self.debounce_timer = self.loop.call_later(2, self.schedule_sync)

    def schedule_sync(self):
        asyncio.run_coroutine_threadsafe(self.sync_function(), self.loop)

# Download a file by ID
async def download(file_uid):
    global entity, metadata
    
    if not os.path.exists(download_name):
        os.makedirs(download_name)

    parsed_files = metadata.get_files()
    if file_uid not in parsed_files:
        print("File with this identifier is not valid.")
        return

    file_info = parsed_files[file_uid]
    chunk_count = file_info.get('chunks', 1)
    parts = file_info.get('parts', [])

    folder_path = os.path.join(download_name, '')
    os.makedirs(folder_path, exist_ok=True)
    
    base_name = file_info["name"]
    extension = file_info["extension"]
    
    actual_path = os.path.join(folder_path, f"{base_name}{extension}")
    counter = 1
    while os.path.exists(actual_path):
        actual_path = os.path.join(folder_path, f"{base_name} #{counter}{extension}")
        counter += 1
    
    print(f"Downloading {file_info['name']}...")

    try:
        with open(actual_path, 'wb') as final_file:
            for i in range(chunk_count):
                for attempt in range(MAX_RETRIES):
                    try:
                        message = await client.get_messages(entity, ids=parts[i])
                        if message and message.file:
                            part_path = f"{actual_path}.tpart{i}"
                            await client.download_media(message, file=part_path)

                            with open(part_path, 'rb') as f:
                                if i == 0:
                                    salt = f.read(16)
                                    iv = f.read(16)
                                encrypted_data_base64 = f.read()

                            encrypted_data = base64_decode(encrypted_data_base64)
                            
                            password = file_info["secret"]
                            key = generate_key(password, salt)
                            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                            decryptor = cipher.decryptor()
                            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                            decompressed_data = decompress_data(decrypted_data)

                            final_file.write(decompressed_data)

                            os.remove(part_path)
                            print(f"Downloaded and processed part {i+1}/{chunk_count}")
                            break
                    except Exception as e:
                        if attempt < MAX_RETRIES - 1:
                            print(f"Download attempt {attempt + 1} failed. Retrying in {RETRY_DELAY} seconds...")
                            await asyncio.sleep(RETRY_DELAY)
                        else:
                            raise e

        print(f"File downloaded and decrypted: {actual_path}")
    except Exception as e:
        print(f"Error downloading file: {e}")

# Global lock for file operations
file_locks = {}

async def get_file_lock(file_path):
    if file_path not in file_locks:
        file_locks[file_path] = asyncio.Lock()
    return file_locks[file_path]

# Define a semaphore to limit concurrent uploads
MAX_CONCURRENT_UPLOADS = 5
upload_semaphore = asyncio.Semaphore(MAX_CONCURRENT_UPLOADS)

async def upload_file(file_path, existing_file_id=None):
    file_lock = await get_file_lock(file_path)
    async with file_lock:
        if not os.path.exists(file_path):
            print(f"File no longer exists: {file_path}")
            return None

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            print(f"Skipping empty file: {file_path}")
            return None
        
        file_name, file_ext = os.path.splitext(file_path)
        rel_path = os.path.relpath(file_path, folder_name)
        file_id = existing_file_id or generate_random_string(14)
        
        # Check if the file content has changed
        if existing_file_id:
            existing_file_info = metadata.get_files().get(existing_file_id)
            if existing_file_info and 'md5' in existing_file_info:
                with open(file_path, 'rb') as f:
                    current_md5 = hashlib.md5(f.read()).hexdigest()
                if current_md5 == existing_file_info['md5']:
                    print(f"File content unchanged, skipping upload: {rel_path}")
                    return existing_file_id

        print(f"Processing file: {file_name} (Size: {format_size(file_size)})")

        try:
            chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
            print(f"File will be split into {chunk_count} chunks")
            
             # Generate the key here
            password = generate_random_string(16)  # Or however you want to generate the password
            salt = os.urandom(16)
            key = generate_key(password, salt)

            async def process_and_upload_chunk(i, key, salt):
                chunk_start = i * CHUNK_SIZE
                chunk_end = min((i + 1) * CHUNK_SIZE, file_size)
                chunk_size = chunk_end - chunk_start

                async with aiofiles.open(file_path, 'rb') as f:
                    await f.seek(chunk_start)
                    chunk = await f.read(chunk_size)

                print(f"Processing chunk {i+1}/{chunk_count}")
                compressed_chunk = compress_data(chunk)
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_chunk = encryptor.update(compressed_chunk) + encryptor.finalize()

                temp_file = f"{file_path}.tpart{i}"
                async with aiofiles.open(temp_file, 'wb') as temp_f:
                    if i == 0:
                        await temp_f.write(salt)
                        await temp_f.write(iv)
                    await temp_f.write(base64_encode(encrypted_chunk))

                print(f"Temporary file created: {temp_file}")

                async with upload_semaphore:
                    for attempt in range(MAX_RETRIES):
                        try:
                            attributes = [types.DocumentAttributeFilename(f"{file_id}.tpart{i}")]
                            async with aiofiles.open(temp_file, 'rb') as f:
                                input_file = await client.upload_file(f, file_name=f"{file_id}.tpart{i}", part_size_kb=512)
                            
                            if existing_file_id:
                                await delete_file_from_cloud(f"{existing_file_id}.tpart{i}")
                            
                            print(f"Uploading {file_name} (Part {i+1}/{chunk_count})...")
                            message = await client.send_file(entity, input_file, attributes=attributes, force_document=True)
                            print(f"Successfully uploaded part {i+1}/{chunk_count}")
                            await asyncio.to_thread(os.remove, temp_file)
                            print(f"Removed temporary file: {temp_file}")
                            return message.id
                        except Exception as e:
                            print(f"Error during upload attempt {attempt + 1}: {str(e)}")
                            if attempt < MAX_RETRIES - 1:
                                print(f"Retrying in {RETRY_DELAY} seconds...")
                                await asyncio.sleep(RETRY_DELAY)
                            else:
                                raise e

            upload_tasks = [process_and_upload_chunk(i, key, salt) for i in range(chunk_count)]
            uploaded_parts = await asyncio.gather(*upload_tasks)
            
            # Calculate and store MD5 hash
            with open(file_path, 'rb') as f:
                file_md5 = hashlib.md5(f.read()).hexdigest()

            await metadata.update_file(file_id, {
                'size': file_size,
                'secret': password,
                'path': rel_path,
                'name': os.path.splitext(file_name)[0],
                'extension': os.path.splitext(file_name)[1],
                'uploaded': datetime.now().isoformat(),
                'modified': os.path.getmtime(file_path),
                'chunks': chunk_count,
                'parts': uploaded_parts,
                'md5': file_md5
            })

            print(f"{'Updated' if existing_file_id else 'Uploaded'} file: {rel_path}")
            return file_id
        except Exception as e:
            print(f"Error uploading file {rel_path}: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            traceback.print_exc()
            return None

async def progress_callback(current, total):
    print(f'Uploaded {current} out of {total} bytes')

async def delete_file_from_cloud(file_id):
    global entity
    async for message in client.iter_messages(entity):
        if message.file and message.file.name == file_id:
            await message.delete()
            break

async def sync_drive():
    global entity, metadata

    try:
        local_files = {}
        for root, dirs, files in os.walk(folder_name):
            for file in files:
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                if file_size == 0:
                    continue
    
                rel_path = os.path.relpath(file_path, folder_name)
                local_files[rel_path] = {
                    'size': file_size,
                    'modified': os.path.getmtime(file_path)
                }
    
        cloud_files = metadata.get_files()
    
        for file_id, file_info in list(cloud_files.items()):
            if file_info['path'] not in local_files:
                await delete_file_from_cloud(file_id)
                await metadata.remove_file(file_id)
                print(f"Deleted file: {file_info['path']}")

        for rel_path, local_info in local_files.items():
            file_path = os.path.join(folder_name, rel_path)
            file_id = next((fid for fid, info in cloud_files.items() if info['path'] == rel_path), None)
    
            if file_id is None:
                new_file_id = await upload_file(file_path)
                if new_file_id:
                    print(f"Uploaded new file: {rel_path}")
            elif (cloud_files[file_id]['size'] != local_info['size'] or 
                  abs(cloud_files[file_id].get('modified', 0) - local_info['modified']) > 1):
                updated_file_id = await upload_file(file_path, file_id)
                if updated_file_id:
                    print(f"Updated file: {rel_path}")

        print("Synchronization completed.")
    except Exception as e:
        print(f"Error during synchronization: {e}")

# Event handlers
@client.on(events.NewMessage(outgoing=True, pattern='/sync'))
async def sync_handler(event):
    try:
        await sync_drive()
        await event.respond('**SYNCHRONIZED** the drive successfully!', link_preview=False)
    except Exception as e:
        print(f"Couldn't synchronize files properly: {e}")
        await event.respond('Failed to synchronize the drive.', link_preview=False)

@client.on(events.NewMessage(outgoing=True, pattern='/upload'))
async def upload_handler(event):
    if event.document:
        file_name_attr = next((x for x in event.media.document.attributes if isinstance(x, types.DocumentAttributeFilename)), None)
        if file_name_attr:
            file_name = file_name_attr.file_name
            message = await event.respond(f'Starting upload of: **{file_name}**', link_preview=False)
            await event.download_media(file=os.path.join(folder_name, file_name))
            try:
                await sync_drive()
                await client.edit_message(event.chat_id, message.id, f'**SUCCESS**, {file_name} has been uploaded to the cloud!', link_preview=False)
            except Exception as e:
                print(f"An error occurred while synchronizing the files: {e}")
                await client.edit_message(event.chat_id, message.id, 'Failed to upload the file.', link_preview=False)
        else:
            await event.respond('Sorry, but there are issues with parsing this document...', link_preview=False)

@client.on(events.NewMessage(outgoing=True, pattern=r'/download (.+)'))
async def download_handler(event):
    file_uid = event.pattern_match.group(1)
    if file_uid not in metadata.get_files():
        await event.respond("File has not been found.", link_preview=False)
    else:
        message = await event.respond(f'Starting download of: **{file_uid}**', link_preview=False)
        await download(file_uid)
        await client.edit_message(event.chat_id, message.id, f'**DOWNLOADED** {file_uid} from the drive successfully!', link_preview=False)

@client.on(events.NewMessage(outgoing=True, pattern='/list'))
async def list_handler(event):
    parsed_files = metadata.get_files()
    if not parsed_files:
        await event.respond("There are no files in metadata to output.", link_preview=False)
        return

    sorted_files = sorted(parsed_files.items(), key=lambda x: x[1]['uploaded'], reverse=True)

    message_content = "📁 File List:\n\n"
    for file_id, file_info in sorted_files:
        file_name = file_info['name']
        file_extension = file_info['extension']
        file_size = format_size(file_info['size'])
        upload_date = datetime.strptime(file_info['uploaded'], '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d %H:%M:%S')
        
        message_content += f"📄 {file_name}{file_extension}\n" \
                           f"   Size: {file_size}\n" \
                           f"   Uploaded: {upload_date}\n" \
                           f"   UID: {file_id}\n\n"

    # Split message if it's too long
    if len(message_content) > 4096:
        for i in range(0, len(message_content), 4096):
            await event.respond(message_content[i:i+4096], link_preview=False)
    else:
        await event.respond(message_content, link_preview=False)

async def main():
    global entity, metadata

    await initialize_folders_and_files()

    await client.start()
    entity = await client.get_entity(invite_link)

    metadata = MetadataHandler(meta_file)

    # Perform initial sync
    await sync_drive()

    # Set up file system watcher
    loop = asyncio.get_running_loop()
    event_handler = FileChangeHandler(loop, sync_drive)
    observer = Observer()
    observer.schedule(event_handler, folder_name, recursive=True)
    observer.start()

    try:
        print("Bot is running. Press Ctrl+C to stop.")
        await client.run_until_disconnected()
    finally:
        observer.stop()
        observer.join()

if __name__ == '__main__':
    with ThreadPoolExecutor() as executor:
        loop = asyncio.get_event_loop()
        loop.set_default_executor(executor)
        loop.run_until_complete(main())