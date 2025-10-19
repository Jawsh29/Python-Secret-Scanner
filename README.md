# Python-Secret-Scanner
Python CLI to scan documents for hardcoded passwords and secrets 

The purpose of this scanner is to improve security when creating software and projects. Run this program before committing to GitHub, sharing files with others, etc. 

To use run "python SecretScanner.py --dir ./test_docs --ext all  -v" in command line to test files for secrets

Arguments
--dir : specify what directory youd would like to scan
--ext: Specify what file extensions you would like to scan. To scan all file types in a file location run "--ext all"
-v: displays what secrets were founs during scan
