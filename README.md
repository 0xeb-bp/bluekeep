# bluekeep
Public work for CVE-2019-0708

### **2019-11-17 Update** ###

Added Windows 7 32bit exploit POC code. 

Using the address within the POC exploit code I had ~80% success rate against my test VM.
It could likely be modfied to increase.

#### **Usage** ####

Replace the buf variable with your shellcode.
Update the host variable to your target.

`python3 win7_32_poc.py`

### **Requirements** ###
* Python3

### **Legal Disclaimer** ###
This project is made for educational and ethical testing purposes only. Usage of for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
