# connective-shit alternative solution

This is the alternative version of connective-shit, using two networked machines where one of them is running the official Connective Native application. It is tested using the Windows executable but it may work under Mac OS/X as well.

## Requirements

Both the proxy and the host applications run under Python. Installing the proxy requires the [nativemessaging](https://github.com/Rayquaza01/nativemessaging) module, but this is not mandatory to run the code. If you know how to install the manifest for native messaging applications you can skip this requirement.

## Installation

### Obtaining the plugin

This is basically the same as for the main solution, just run the `get_connective_plugin.py` script included in the main directory of this repository.

### Installing the browser plugin

This should be straightforward. Go to the `connective-downloads` directory created in the previous step and open `connective_signing_extension-1.0.4.xpi` in your web browser and follow the installation instructions.

### Installing the proxy

This script will be started by your browser whenever the Connective Browser Plugin receives the command to do so and will forward all requests to the machine where the card reader is connected.

First of all, open the file `connective-proxy.py` and modify the HOST variable on top to the ip address or hostname of the machine where the card reader is connected.

Next, install nativemessaging using `pip install nativemessaging` and run `nativemessaging-install.py firefox` or `nativemessaging-install.py chrome` depending on your browser. For other browsers you have to investigate where to install `native-manifest.json`. Make sure you run this command from the client-server directory to install the correct native messaging application.

Note that the nativemessaging package is not required for the proxy to run, you can uninstall it afterwards. A possible addition would be to install the proxy automatically by the backend for user convenience.

Also note that the full path to the proxy is saved in your browser's native messaging configuration. This means that if you want to move the proxy to another location after installation you are also required to re-run `nativemessaging-install.py` with the appropriate parameter.

### Installing the host

Extract the native application from the installer using 7zip: `7z x connective-downloads/connective-plugin-installer-local-2.0.9.msi firefox.extension.native`. Note we are extracting the Firefox version, the Chrome version is identical. Rename the file to `extension-native.exe` to avoid confusion.

Copy both `extension-native.exe` and `connective-host.py` to the host machine and modify the HOST variable on top to the ip address where the server should listen. It is the public ip address of the machine where the card reader is connected and where `connective-host.py` will run.

## Use

The host should be running on the machine where the card reader is connected before trying to log in or sign a document on the machine where the proxy is installed.

