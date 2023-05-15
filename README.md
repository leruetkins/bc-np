# bc-np
App to Clean Backups

This program was written in whole or in part with ChatGPT. If you need to increase the code and add new features, you are always welcome.

Before running the program, modify the config.json file to suit your needs:
period - time in seconds after which the deletion will be repeated

port - the port on which the http server is started

endpoints - an array with entry points with parameters, you can add the folders you need, network paths are also supported

count - the number of files to keep in the given folder

enabled - enable or disable the endpoint, set to "true" to get started

filter - excludes files with extension by mask, entire files or folders from deletion.

Once started, you can open http server on port 8000 to see configuration file or log file http://localhost:8000
