import zipfile

fileName = "C:\Users\Patrick\Documents\PROGRAMMING\PYTHON\ViolentPythonStuff\ZipFileCracker\zip.zip" # raw_input("Please type the full directory of the file: ")
file = zipfile.ZipFile(fileName)
file.extractall(pwd="secret")