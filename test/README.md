# Troubleshoot guide

There are a few components here which may all act in an unusual way. The Connective server is usually very unclear about what is going wrong, but there are some steps you can take to figure out what happens.

## Everything installed, but website is still asking to install Connective Browser Package

If you see this message on Windows or Mac OSX it means you didn't correctly install the official Connective browser package. On Linux there are several possibilities:
- The browser plugin is not correctly installed. This is the least likely cause and it can easily be checked in your browser's addon settings.
- The `connective-backend.py` script is incorrectly installed or not running properly.
  - Verify if the nativemessaging host json file is correctly installed as `~/.mozilla/native-messaging-hosts/com.connective.signer.json` (for Firefox) or `~/.config/google-chrome/NativeMessagingHosts/com.connective.signer.json` (for Chrome).
  - The nativemessaging host json file contains the full path to the `connective-backend.py` script, verify if that is correct
  - You should be able to run the `connective-backend.py` script in a terminal window. See below how to do this and what the results should be.

## Run `connective-backend.py` in a terminal window

1. Change the directory to the test directory
2. Run `create-messages.py`
3. Run `../connective-backend.py < get_readers.txt`
4. The output should contain the reader name, e.g. `"name": "VASCO DIGIPASS 870 [CCID] 00 00"`. Copy the name to the top of `create-messages.py` and run the script again
5. You can now test any message by running `../connective-backend.py < [message]`, replacing \[message\] by one of the generated message files. The script should run without errors, in some cases a pincode will be requested on your screen or on the reader.

## Run `connective-backend.py` in a web browser

If you are confident the installation of both the browser plugin and the `connective-backend.py` script succeeded, you can test it in a browser.

1. Open the browser log using ctrl-shift-J. Please note this is different from F12 > console!
2. Open test/protocoltest.html in the web browser where you installed the Connective plugin
3. Make sure the cardreader is attached and click on _GET__READERS_. There is no need to modify the message so you can click _Send request_ right away. If the command succeeds, the reader textfield on top will be filled automatically. In case there is a failure you should look at the communication at the bottom and the browser log.
4. You can now continue to test any other message. They should all return valid data without errors in the browser log.

## Bug reports

If you encounter an error which you cannot resolve using the above information, please file a bug report. Explain in which stage of the logon or signing procedure the error happened and include the output of the browser log (or the script in case you were testing in a terminal window).

