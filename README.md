## CST Signer

---

### Introduction
The CST signer tool works in conjunction with the [Code Signing Tool (CST)](https://www.nxp.com/webapp/Download?colCode=IMX_CST_TOOL_NEW&appType=license&location=null)
provided by NXP. This tool allows a way to automate the signing process in 
conjunction with a configuration file that can be populated with necessary 
inputs. In addition, this tool parses the "to be signed" image and extracts the 
offset and length information needed to sign the image, thus reducing the 
possible human error while signing.

---

### Prerequisite
This tool requires the CST to be present at a preset location. The tool can be 
invoked and the path to CST must be provided using the environment variable 
***CST_PATH***.

---

### Build

Build this tool using `make` command.

---

### Sign images using hardware backed cryptographic keys "--pkcs11"
This introduces a few changes to nxp-cst--signer for secure hardware signing.
This code is experimental, and has been tested with AHAB mimx9352, iMX.8MP, and i.MX8MN.
Have not tested with fastboot on i.MX8MP or i.MX8MN.

Steps required 
- Works currently on linux
- build nxp-cst-signer
- build cst-3.4.1 (make sure the copmiled binary is in ${CST_PATH}/code/build director)
- make sure that you have PKCS11_MODULE_PATH to the pkcs#11 library when executing cst-signer
- make sure to set the PKCS#11 as key in the cfg.
- Set private key in the cfg : "pkcs11# url". The URL can be fetched using: 
```
p11tool --provider $PKCS11_MODULE_PATH --list-all-privkeys --login
# --only-urls can be added to reduce the output
```
- Had to remove the "object" from the pkcs11 url to make it work, needs to be investigated.


Note: 
- The benfit of using this is that it protects private key from exposure.
- Make sure that you use a have a recoverable backup of your private key. And consult the manual from pkcs11 key
- The solution protects the private key from exposure of normal usage.

PKCS#11 is experimental support is added for linux, append --pkcs11
In order for this to work, PKCS11_MODULE_PATH must be set before invoking 

----

### Run

To run this tool, along with CST, you would also need to have the CSF config 
file filled with appropriate values based on the setup.

To help start the signing process, sample CSF configuration files have been 
provided as part of this package.

Invoke the cst_signer command as follows (example):
`CST_PATH=<cst> ./cst_signer -i flash.bin -c csf.cfg`

---

### Results

This tool generates final signed binary as "**signed-\<input_filename\>**". It 
also creates the CSF files used to generate the final signed binary.
