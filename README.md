


All PeerBrain projects have moved to a dedicated GitHub organisation.
https://github.com/PeerBrain

Please note, the old repository, shandralor/PeerBrain is no longer used and has been replaced with the new repos in the organisation.
The CLI, GUI and server are now in separate repositories.

Significant Repo Changes:
The CLI client is now here: https://github.com/PeerBrain/cli-client
The GUI client is now here: https://github.com/PeerBrain/gui-client
The server source code is now here: https://github.com/PeerBrain/server

Any other repositories related to the project have also been moved to the GitHub organisation.

If you want more updates about Peer Brain projects, make sure to follow the GitHub organisation and star the new repositories! 
-------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------

# Peer Brain - A Decentralized P2P Social Network App

This open-source project implements a peer-to-peer social network app where users are represented as brain cells. It is completely decentralized and there is no central authority or recommendation algorithms, nor is there any censorship. Messages are propagated between users in a meritocratic way, and users have control over the strength of the signals they receive. This allows for more free and open communication between users.

If you want to contribute, you can fork this repository and issue pull requests! Feel free to use ChatGPT or OpenAI to help you with the coding.

### Table of Contents  
1. [Updates](#Updates)
2. [How does the open-source workflow work?](#how-does-the-open-source-workflow-work)
3. [Encryption Mechanism](#encryption-mechanism)
4. [Installation/Instructions](#installationinstructions)
5. [Resources](#resources) 

### Updates

**2023/03/15**
* Code clean-up
* User account creation now requires email verification before allowing you to login
* Password reset functionality has been added


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
![PeerBrain1](https://user-images.githubusercontent.com/8386876/225581439-5ac89a92-eda2-4c85-bfb4-27ff6ab90482.png)
6. After successful registration, try to login into the application with details you have used during registration process.
![PeerBrain2](https://user-images.githubusercontent.com/8386876/225581428-5cc627c1-4625-4ac1-a3dc-64798d9befd8.png)
7. After successful login, you will be able to see the Main menu as below:
![PeerBrain3](https://user-images.githubusercontent.com/8386876/225581434-1d116bf4-953e-4680-80b1-e291a3e9d8ba.png)
8. Make sure you have generated the keys prior exploring the application. To generate keys Navigate to Account details section, select generate the keys(2nd option).

Congratulations :tada: and Thanks for making it till here. Please free feel to explore the application menu :relaxed:. Happy journey!


## Resources
Here are some resources about this project:
* [Finxter Youtube project start video](https://youtu.be/GaQGfzTiHTc)
    -The video that started it all.
    
* [Git basics](https://www.freecodecamp.org/news/learn-the-basics-of-git-in-under-10-minutes-da548267cc91/)
    -This article talks about how to use Git versioning, which comes in handy when working on open source projects.

* [Symmetric Key Exchange Server](https://github.com/shandralor/Symmetric-Key-Exchange)
    -This server takes care of storing the symmetric keys and sending back the encrypted versions of these when a user wants to read a friends messages.
    It is a part of this project but it doesn't share any resources with it. The two are separated to ensure the security of the symmetric keys.


------------------------------------------------------------------------------------------------
[![linting: pylint](https://img.shields.io/badge/linting-pylint-yellowgreen)](https://github.com/PyCQA/pylint)
![GitHub issues](https://img.shields.io/github/issues-raw/shandralor/PeerBrain?style=plastic)
