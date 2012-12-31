LG DZ Firmware Decoding Script
==============================

This is a simple python script to decode LG DZ firmware files, such as those found in Windows 7 Phones. This script probably does not do anything other than decode the firmware files and output the components, the recreated firmware files are probably non-functional. *Do not try to flash the recompiled firmware file to a device.*

Usage
-----

To decode a DZ file, the input file ```inputfilename.dz``` will be decoded and the components will be outputted to the specified directory.

	./python dztool.py -m decode -i inputfilename.dz -o dir

This will output a number of component files into the directory ```dir```, including a configuration file that can be used to reconstruct the dz file from the components. *Please note that you must be in the output directory for this command to work.*

To create a DZ file from the decoded components the following command can be used:
	./python dztool.py -m create

This will output a compiled dz firmware file ```outfile.dz```.

License
-------

This application is licensed under an [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)

    Copyright 2012 David Ellefsen

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

Disclamer
---------

This application should be considered in an alpha state of development, should it eat your files or brick a device, be it on your own head.
