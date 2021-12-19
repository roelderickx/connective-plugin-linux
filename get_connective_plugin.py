#!/usr/bin/python

# -*- coding: utf-8 -*-

import os
import requests
import json

BASE_URL = 'https://plugin.connective.eu/'

# create directory for the downloaded files
try:
    os.mkdir('connective-downloads')
except FileExistsError:
    pass

# download the index
download_index = json.loads(requests.get(BASE_URL + 'download-index.json').content)

# download the windows plugin
windows_plugin = requests.get(BASE_URL + download_index['windows-plugin-local:latest'])
outfile = 'connective-downloads/' + os.path.basename(download_index['windows-plugin-local:latest'])
open(outfile, 'wb').write(windows_plugin.content)

# download the browser plugin
browser_plugin = requests.get(BASE_URL + download_index['firefox-native-extension:latest'])
outfile = 'connective-downloads/' + os.path.basename(download_index['firefox-native-extension:latest'])
open(outfile, 'wb').write(browser_plugin.content)

