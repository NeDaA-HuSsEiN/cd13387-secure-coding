# Project Instructions
# Step 1
Analyze the following architecture document and perform a simplified threat modeling.

First, identify relevant assets from the design document and then identify threats using STRIDE for each asset. Then based on the threats, provide suggestions for mitigations.

Architecture of embedded devices and server
Architecture of embedded devices and server

# Step 2.
Based on the device functions define a user role matrix. The matrix should show different functions that each role can do. Consider the principle of least privilege when defining the roles and functions.

# Step 3.
Instructions: Clone the project from github if you haven't already:

$ git clone https://github.com/udacity/cd13387-secure-coding.git
Go to the project folder

$ cd ~/cd13387-secure-coding/project/starter/step3
Build the container

$ docker build -t project_step3 .
Run the container to launch the login app

$ docker run -it --rm project_step3
Review the code/software to find hardcoded and plaintext passwords.

Modify the code to remove any hardcoded passwords in the code.

Review the provided hash_utils.c, hash_utils.h, and generate_hashed_users.c to understand what the functions do.

First store all the plaintext and hardcoded passwords in the users.txt. Please note that this is a temporary file containing plaintext passwords that will be processed to generate the hashed passwords. In a production device this file should not be included but for this exercise this file can be left since we are still in a development environment.

Compile and run generate_hashed_users.c (in the Dockerfile or start.sh) to create hashed_users.txt which includes the salt and hashed passwords before login starts (in start.sh).

Modify login.c to read all passwords stored as salted hashes in a separate file (hashed_users.txt) to prevent reading stored plaintext passwords.

Modify login.c to hash the inputted password and compare to the read hashed password. Use the functions provided in hash_utils.c (make sure to include "hash_utils.h" in the modified login.c).

# Step 4.
Instructions: Clone the project from github if you haven't already:

$ git clone https://github.com/udacity/cd13387-secure-coding.git
Go to the project folder

$ cd ~/cd13387-secure-coding/project/starter/step4
Copy the login.c from the step3 folder into the step4 folder

cp ~/cd13387-secure-coding/project/starter/step3/login.c ~/cd13387-secure-coding/project/starter/step4/
Build the container

$ docker build -t project_step4 .
Run the container to launch the login app

$ docker run -it --rm project_step4
There is a buffer overflow vulnerability in the program. Find and fix the vulnerability. To help understand the crash, the login is automatically started with gdb.

To prevent an attacker from bruteforcing attacks on the device, add a lockout threshold counter to the login function. Apply a timer lock after 3 failed attempts for the same user. That is, login is locked for 5 seconds. After 5 seconds, if there is another failed attempt, it will be locked again for another 5 seconds. If login is successful, the failed attempt counter is reset to 0.

The generate_hashed_users.c has been updated to also include an initial counter of 0 as the fourth value on each line in the hashed_users.txt file.

Update login.c with a new function to update the hashed_users.txt file with the counter value after login attempts.

# Step 5.
Instructions: Clone the project from github if you haven't already:

$ git clone https://github.com/udacity/cd13387-secure-coding.git
Go to the project folder

$ cd ~/cd13387-secure-coding/project/starter/step5
Build the container

$ docker build -t project_step5 .
Run the container

$ docker run -it --rm project_step5
Check the software for any legacy services and disable them (e.g., ftpd, rlogind, rexec, rshell, telnetd, etc.). Remember to scan using nmap or check with netstat.

After disabling the services and removing any other unnecessary commands in the Dockerfile (but leave the net-tools and nmap), update the Dockerfile according to below to run the /app/start.sh

Specify the command to run the program
CMD ["/bin/bash", "/app/start.sh"]
Build the container

$ docker build -t project_step5 .
Run the container

$ docker run -it --name step5 project_step5
From another terminal, execute bash within the container

$ docker exec -it step5 /bin/bash
Scan again with nmap or check with netstat that there are no legacy services running.

Test that the login app works as it should. Review the c code files to find any non-production, dead or unused code, and remove them. Rebuild and run it again to make sure the login app works.

# Step 6.
Instructions: Clone the project from github if you haven't already:

$ git clone https://github.com/udacity/cd13387-secure-coding.git
Go to the project folder

$ cd ~/cd13387-secure-coding/project/starter/step6
First generate a root CA key (rootCA.key):

$ openssl genpkey -algorithm RSA -out rootCA.key -aes256
and root CA certificate (self-signed) (rootCA.crt):

$ openssl req -x509 -new -key rootCA.key -sha256 -days 3650 -out rootCA.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=RootCA"
Then generate the private key (server.key), certificate signing request (CSR) for the server (server.csr) and sign the server certificate (server.crt) with the root CA .

Repeat the steps for the client, i.e., generate the private key (client.key), certificate signing request (CSR) for the client (client.csr) and sign the client certificate (client.crt) with the root CA.

Command to generate private key (need to be adjusted):

openssl genpkey -algorithm RSA -out <which.key>
Command to create a Certificate Signing Request (need to be adjusted):

openssl req -new -key <which.key> -out <which.csr> -subj "/C=US/ST=State/L=City/O=Organization/CN=<which.CN>"
Command to sign the certificate with the root CA (need to be adjusted):

openssl x509 -req -in <which.csr> -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out <which.crt> -days 365 -sha256
This project folder contains Dockerfile for server and client, respectively. Copy the generated certificates and keys into the corresponding server/client folders.

The folder structure should look like the following:

project/

│

├── server/

│ ├── Dockerfile

│ ├── server.c

│ ├── rootCA.crt

│ ├── server.crt

│ ├── server.key

│ ├── software_update.bin

│

└── client/

├── Dockerfile

├── client.c

├── rootCA.crt

├── client.crt

├── client.key

Use Docker network to communicate between the docker containers:

First, create the Docker network:

$ docker network create mtls-network
Build and run the server:

$ docker build -t mtls-server ./server
$ docker run -it --name server --network mtls-network mtls-server
Modify the client.c file to make sure it compiles. The client should connect to the server, receive the software_update.bin file, and save it as received_update.bin. This setup secures the file transfer with mTLS, ensuring both server and client certificates are verified.

Build and run the client:

$ docker build -t mtls-client ./client
$ docker run -it --rm --name client --network mtls-network mtls-client
First test the communication from client to server (from within the client container) using ping or telnet (e.g., ping server).

Command to connect with openssl manually (need to be adjusted):

# openssl s_client -connect <server-ip>:8443 -cert <path-to-client-cert.crt> -key <path-to-client-key.key>
Verify that the connection works and copy and paste the output into a file named output.txt as part of the submission.

Run the ./client command from within the client container:

# ./client
And verify that the received data in "received_update.bin" is correct using the following command.

cat received_update.bin |strings
The first bytes are: SOFTWAREUPDATE and the last bytes are: CHECKSUM, and total size is 1034 bytes.

Copy the output to the existing output.txt file.

# Step 7.
Instructions: Continue from Step 6 and use the same folders.

This step involves sending a secure software update from the server to the embedded device (client).

First, generate a "Software Update" certificate signed by root CA by following the same steps described in Step 6, i.e., generate the private key (software_update.key), certificate signing request (CSR) (software_update.csr) and sign the certificate (software_update.crt) with the root CA.

Then, copy the software_update.key and software_update.crt to the /server folder and sign the software_update.bin file with the software update private key (software_update.key) to create a digital signature (software_update.sig)

openssl dgst -sha256 -sign software_update.key -out software_update.sig software_update.bin
Generate a checksum using SHA256 of the update file.

sha256sum software_update.bin > software_update.checksum
Next, archive the files (software_update.bin, software_update.sig, software_update.checksum and software_update.crt) and store the software_package.zip file on the server.

Modify server.c to send the software_package.zip instead of software_update.bin.

Modify client.c to receive received_package.zip instead of received_update.bin.

First, create the Docker network if it does not already exist:

$ docker network create mtls-network
Build and run the server:

$ docker build -t mtls-server ./server
$ docker run -it --name server --network mtls-network mtls-server
Build and run the client:

$ docker build -t mtls-client ./client
$ docker run -it --rm --name client --network mtls-network mtls-client
Run the ./client command from within the client container:

./client
This stores the received_package.zip on the client.

Copy the zip file from the client container to the host:

docker cp client:/app/received_package.zip ~/cd13387-secure-coding/project/starter/step7/client
Unzip the package on the host and check that the contents seem correct (should contain software_update.bin, software_update.sig, software_update.checksum and software_update.crt).

Create verify_update.c in the /client folder on the host. verify_update.c should verify that the certificate (software_update.crt) is signed by the root CA (rootCA.crt), then use the software update certificate (software_update.crt) to verify the digital signature (software_update.sig) of the software update (software_update.bin). Finally, the checksum of the software update (software_update.bin) should be compared against the provided checksum (software_update.checksum). If all verifications pass, the update is valid.

Tip:
If there are conflicts with containers already running:

to remove all containers

docker rm -f $(docker ps -a -q)
to remove all images

docker rmi -f $(docker images -q)
