# connective-plugin-linux alternative solution

This is the alternative version of connective-plugin-linux, using two networked machines where one of them is running the official Connective Native application. It is tested using the Windows executable but it may work under Mac OS/X as well.

## Requirements

Both the proxy and the host applications run under Python. Installing the proxy requires the [nativemessaging-ng](https://github.com/roelderickx/nativemessaging-ng) module, but this is not mandatory to run the code. If you know how to install the manifest for native messaging applications you can skip this requirement.

## Installation

### Obtaining the plugin

Trying to install the Connective browser package under Linux results in a message `This operating system is not supported`. You are not even able to download anything.

To obtain the necessary files anyway run the `get_connective_plugin.py` script included in this repository. A subdirectory `connective-downloads` will be created, containing the installer for both the browser plugin and the windows native application.

### Installing the browser plugin

#### Firefox

install the extension from [the firefox addon store](https://addons.mozilla.org/en-US/firefox/addon/connective-signing-ext/).

#### Google Chrome

install the extension from [the chrome web store](https://chromewebstore.google.com/detail/connective-signing-extens/kclpjmhngbacampgcdojmiedamjbgjjm?utm_source=chrome-app-launcher-info-dialog).

#### Other browsers

If no addon store exists for your browser you have to download and install the extension manually. Run the `get_connective_plugin.py` script included in this repository. A subdirectory `connective-downloads` will be created, containing the installer for the browser plugin.

Installation should be straightforward. Go to the `connective-downloads` directory created in the previous step, open `connective_signing_extension-1.0.12.xpi` in your web browser and follow the installation instructions.

Note that version 1.0.12 is not the latest version and does not work as provided. You need to update the plugin via the settings in your browser.

### Installing the proxy

This script will be started by your browser whenever the Connective Browser Plugin receives the command to do so and will forward all requests to the machine where the card reader is connected.

First of all, open the file `connective-proxy.py` and modify the HOST variable on top to the ip address or hostname of the machine where the card reader is connected.

Next, install the nativemessaging-ng package and run `nativemessaging-ng install firefox` or `nativemessaging-ng install chrome` depending on your browser. Make sure you run this command from the client-server directory to install the correct native messaging application. A modified version of `native-manifest.json` will be installed in your browser's configuration, containing the full path to `connective-proxy.py`. Keep this in mind when you want to move the proxy to another location, you will need to re-run `nativemessaging-ng install` with the appropriate parameter in that case.

### Installing the host

Extract the native application from the installer using 7zip: `7z x connective-downloads/connective-plugin-installer-local-2.0.9.msi firefox.extension.native`. You can also extract the chrome version, but it doesn't matter since both versions are identical. Rename the file to `extension-native.exe` to avoid confusion.

Copy both `extension-native.exe` and `connective-host.py` to the host machine and modify the HOST variable on top to the ip address where the server should listen. It is the public ip address of the machine where the card reader is connected and where `connective-host.py` will run.

## Use

The host should be running on the machine where the card reader is connected before trying to log in or sign a document on the machine where the proxy is installed.
