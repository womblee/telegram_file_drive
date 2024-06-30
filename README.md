# Telegram File Drive
 Telegram based cloud storage solution with **AES256** encryption and an integrated user interface.

# Description
This program allows you to synchronize your files in a specific folder with a Telegram channel.

* All files are **encrypted and cannot be viewed by anyone** but you!

* Big files (20 MB+) are split into several smaller chunks.

* Files are compressed.
  
* Files are stored without extensions in a random string format, and it loops through every one of them until it finds the one you need (usually doesn't take a long time, unless you have 1000+ files).

![image](https://github.com/womblee/telegram_file_drive/assets/52250786/d69e55d8-d625-48db-849f-89b752af25bf)

Files are downloaded via their **UID**, since we can't really keep track of everything and store everything in the filename itself.
That's why we use a **metadata file** which stores every info.

Multi-directory support is present, and you can even upload files with extensions which will automatically get their extension!

# Commands list

![image](https://github.com/womblee/telegram_file_drive/assets/52250786/8744a946-c544-49e2-9209-037b119e0659)
* **/upload** - lets you upload and encrypt your file to the Telegram cloud
* **/sync** - synchronizes your uploads folder with the Telegram cloud [tech]
* **/download *%file_uid%*** - downloads a file by its UID in the specified folder
* **/list** - gives an embed of every file you store in the Telegram cloud

# Installation
![image](https://github.com/womblee/telegram_file_drive/assets/52250786/dda1f2eb-1052-4a1d-bb1c-fc4af3f312d6)

This is basically how your folder should look like.
Edit 'app_id' and 'app_hash' to your own one, and login via the CMD afterwards. Voila.
Oh, and also make sure you change the 'invite_link' to a **PRIVATE** telegram **CHANNEL**.
# PIP
telethon, cryptography, aiofiles, hashlib, watchdog, zlib

# Credits
Inspired by 'Dev Detour' YouTube channel.
I made everything from scratch and I barely watched the video, but it's still a pretty cool concept.
