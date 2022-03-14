You will need the following files from within the Jenkins home dir

* master.key
* hudson.util.Secret
* credentials.xml

Run the script:
```
./decrypt.py ./master.key ./hudson.util.Secret ./credentials.xml
```