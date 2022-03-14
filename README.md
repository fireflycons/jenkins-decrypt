# Jenkins Password Decryptor

You will need the following files from within the Jenkins home directory:

* `master.key`
* `hudson.util.Secret`
* `credentials.xml` or a secret cipehrtext which looks like base64 surrounded with `{}`

## Decrypt secrets in credentials.xml

This will decrypyt secrets of the following types

* `com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImp`
* `com.cloudbees.plugins.credentials.impl.StringCredentialsImpl`
* `com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey`
* `com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl`
* `com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential`

Others can easily be added if you add the appropriate code to extract the secret type from the XML.

```
./decrypt.py path/to/master.key path/to/hudson.util.Secret path/to/credentials.xml
```

## Decrypt a single ciphertext

```
./decrypt.py path/to/master.key path/to/hudson.util.Secret '{ciphertext}'
```