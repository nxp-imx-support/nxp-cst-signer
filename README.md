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
