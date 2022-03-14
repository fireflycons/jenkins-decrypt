#!/usr/bin/env python3

from cgitb import text
import re
import sys
import base64
import xml.etree.ElementTree as ET
from hashlib import sha256
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES

MAGIC = b"::::MAGIC::::"

def usage():
  print("./decrypt.py <master.key> <hudson.util.Secret> <credentials.xml>")
  sys.exit(0)

def decryptNewPassword(secret, p):
  p = p[1:] #Strip the version

  # Get the length of the IV, almost certainly 16 bytes, but calculating for completeness sake
  iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

  # Strip the iv length
  p = p[4:]

  # Get the data length
  data_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

  # Strip the data length
  p = p[4:]

  iv = p[:iv_length]

  p = p[iv_length:]

  o = AES.new(secret, AES.MODE_CBC, iv)

  decrypted_p = o.decrypt(p)

  # We may need to strip PKCS7 padding
  fully_decrypted_blocks = decrypted_p[:-16]
  possibly_padded_block = decrypted_p[-16:]
  padding_length = possibly_padded_block[-1]
  if padding_length <= 16: # Less than size of one block, so we have padding
    possibly_padded_block = possibly_padded_block[:-padding_length]

  pw = fully_decrypted_blocks + possibly_padded_block
  pw = pw.decode('utf-8')
  return pw

def decryptOldPassword(secret, p):
  # Copying the old code, I have not verified if it works
  o = AES.new(secret, AES.MODE_ECB)
  x = o.decrypt(p)
  assert MAGIC in x
  return re.findall('(.*)' + MAGIC, x)[0]

def main():
  if len(sys.argv) != 4:
    usage()

  master_key = open(sys.argv[1], 'rb').read()
  hudson_secret_key = open(sys.argv[2], 'rb').read()
  hashed_master_key = sha256(master_key).digest()[:16]
  o = AES.new(hashed_master_key, AES.MODE_ECB)
  secret = o.decrypt(hudson_secret_key)

  secret = secret[:-16]
  secret = secret[:16]

  credentials = open(sys.argv[3]).read()
  xml = ET.parse(sys.argv[3])

  password_entries = []
  for elem in xml._root.iter('com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl'):
    password_entries.append ({
      'Type': 'UsernamePasswordCredentials',
      'Id': elem.find('id').text,
      'Username': elem.find('username').text,
      'CipherText': elem.find('password').text
    })

  for elem in xml._root.iter('com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey'):
    password_entries.append ({
      'Type': 'BasicSSHUserPrivateKey',
      'Id': elem.find('id').text,
      'Username': elem.find('username').text,
      'CipherText': elem.find('privateKeySource').find('privateKey').text
    })

  for elem in xml._root.iter('com.cloudbees.plugins.credentials.impl.StringCredentialsImpl'):
    password_entries.append ({
      'Type': 'StringCredentials',
      'Id': elem.find('id').text,
      'CipherText': elem.find('secret').text
    })

  for elem in xml._root.iter('com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl'):
    password_entries.append ({
      'Type': 'GitLabApiToken',
      'Id': elem.find('id').text,
      'CipherText': elem.find('apiToken').text
    })

  for elem in xml._root.iter('com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential'):
    password_entries.append ({
      'Type': 'VaultAppRoleCredential',
      'Id': elem.find('id').text,
      'CipherText': elem.find('secretId').text,
      'RoleId': elem.find('roleId').text,
      'Path': elem.find('path').text
    })

  # You can find the password format at https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/util/Secret.java#L167-L216

  for password_entry in password_entries:
    p = base64.decodebytes(bytes(password_entry['CipherText'], 'utf-8'))

    # Get payload version
    payload_version = p[0]
    if payload_version == 1:
      password = decryptNewPassword(secret, p)
    else: # Assuming we don't have a V2 payload, seeing as current crypto isn't horrible that's a fair assumption
      password = decryptOldPassword(secret,p)

    print (password_entry['Type'])
    print ('-' * len(password_entry['Type']))
    print(f'Id:       {password_entry["Id"]}')

    if password_entry['Type'] == 'UsernamePasswordCredentials':
      print(f'Username: {password_entry["Username"]}')
      print(f'Password: {password}')
    elif password_entry['Type'] == 'BasicSSHUserPrivateKey':
      print(f'Username: {password_entry["Username"]}')
      print('Private Key:')
      print(password)
    elif password_entry['Type'] == 'StringCredentials':
      print(f'Password: {password}')
    elif password_entry['Type'] == 'GitLabApiToken':
      print(f'Token: {password}')
    elif password_entry['Type'] == 'VaultAppRoleCredential':
      print(f'Role ID  : {password_entry["RoleId"]}')
      print(f'Path     : {password_entry["Path"]}')
      print(f'Secret ID: {password}')

    print ('')
    print ('=' * 80)
    print ('')

if __name__ == '__main__':
  main()