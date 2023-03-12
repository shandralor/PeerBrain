
# Peer Brain - A Decentralized P2P Social Network App


This open-source project implements a peer-to-peer social network app where users are represented as brain cells. It is completely decentralized and there is no central authority or recommendation algorithms, nor is there any censorship. Messages are propagated between users in a meritocratic way, and users have control over the strength of the signals they receive. This allows for more free and open communication between users.

If you want to contribute, you can fork this repository and issue pull requests! Feel free to use ChatGPT or OpenAI to help you with the coding.

### Table of Contents  
1. [How does the open-source workflow work?](#how-does-the-open-source-workflow-work)
2. [Encryption Mechanism](#encryption-mechanism)
3. [Installation/Instructions](#installationinstructions)
4. [Resources](#resources) 


### How does the open-source workflow work?
The open-source workflow is a process by which users can contribute to a project. It is typically done through a system like GitHub, where users can fork, or copy, a repository, make changes to it, and then submit a pull request. The project maintainers then review the changes and either accept or reject them. If accepted, the changes are merged into the main repository. This process allows for collaboration between users and for projects to be updated and improved quickly.

## Encryption Mechanism
1. Load symmetric key.
2. Encrypt the user entered message using the symmetric key.
3. Fetch the public key from the server.
4. Encrypt the symmetric key using the public key.
5. Decrypt the encrypted symmetric key using the private key.
6. Decrypt the encrypted message using decrypted symmetric key.   
This is encryption cycle for each message we write or read. 

## Installation/Instructions
1. Clone the PeerBrain Repo to your local machine
2. Now navigate to client directory
3. Install all the packages from the requirements.txt file using command:
```bash
pip install -r requirements.txt
```
4. After successful installation, start the client service. Don't change anything in the code :)
When everything runs fine as expected, you will see the menu as below:
5. First step is to register yourself with the application.Select option 2 to register.
![peerbrain1](https://user-images.githubusercontent.com/24318892/221877115-6374e40a-856e-48e0-af29-d57d7aab202c.png)
6. After successful registration, try to login into the application with details you have used during registration process.
![peerbrain2](https://user-images.githubusercontent.com/24318892/221877274-dc8420e6-36b2-4c20-be60-13669c9221bd.png)
7. After successful login, you will be able to see the Main menu as below:
![peerbrain3](https://user-images.githubusercontent.com/24318892/221877324-690cecee-042e-4ea5-82a6-b7cbffdf622e.png)
8. Make sure you have generated the keys prior exploring the application. To generate keys Navigate to Account details section, select generate the keys(2nd option).

Congratulations :tada: and Thanks for making it till here. Please free feel to explore the application menu :relaxed:. Happy journey!


## Resources
Here are some resources about this project:
* [Finxter Youtube project start video](https://youtu.be/GaQGfzTiHTc)
* [Git basics](https://www.freecodecamp.org/news/learn-the-basics-of-git-in-under-10-minutes-da548267cc91/)

* [Symmetric Key Exchange Server](https://github.com/shandralor/Symmetric-Key-Exchange)
    -This server takes care of storing the symmetric keys and sending back the encrypted versions of these when a user wants to read a friends messages.
    It is a part of this project but it doesn't share any resources with it. The two are separated to ensure the security of the symmetric keys.


------------------------------------------------------------------------------------------------
[![linting: pylint](https://img.shields.io/badge/linting-pylint-yellowgreen)](https://github.com/PyCQA/pylint)
[![GitHub issues](https://img.shields.io/github/issues-raw/shandralor/peerbrain?style=plastic)]
