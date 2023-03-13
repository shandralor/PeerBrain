"""Brainwaves cli client file"""
import getpass
import os
import json
import requests
import base64
from typing import List, Union
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from encrypt_data import generate_keypair, load_private_key, detect_private_key, \
    save_private_key, encrypt_message_symmetrical, decrypt_message, generate_sym_key, load_sym_key, \
        detect_sym_key, detect_public_key, save_public_key, load_public_key

from client_functions import create_token, get_token, get_account_info, get_sym_key, post_thought, register_user, \
    add_user_friends, get_user_friends, get_all_users, get_thoughts_for_user, wrap_encrypt_sym_key, upload_keystore, \
        login_with_token, log_out


def main():
    """Display the main menu and prompt the user to choose an option."""    
    
    #server_url = "http://127.0.0.1:8000/"
    server_url = "https://peerbrain.teckhawk.be/"
    
    authenticated = False

    print()
    print("Welcome to version 0.2 of the Brainwaves P2P client!")
    print("-------------------------------------------------------------------")
    print(f"The currently set server url is {server_url}")
    print("-------------------------------------------------------------------")
    print()
    print("Please select what you want to do from the menu below.")

    #MENU SHOWING WHILE WE ARE NOT LOGGED IN OR AUTHENTICATED WITH TOKEN
    if not authenticated:
        while authenticated == False:
            print("1. Log in to the current server.")
            print("2. Register account on the current server")
            print("3. Change server.")
            print("Q to exit")
            choice = input(">> ")
            
            if choice == "1":
                try:
                    # username = input("Please enter your username: ")
                    # password = getpass.getpass(prompt = "Please enter your password: ")
                    login_with_token(server_url)
                    authenticated = True
                except KeyError:
                    print("---")
                    print("Username/Password incorrect")
                    print("---")
            elif choice == "2":
                username = input("Enter your username: ")
                user_email = input("Enter your email address: ")
                user_password = getpass.getpass(prompt = "Please enter a password: ")
                confirm_password = getpass.getpass(prompt = "Confirm your password: ")
                if user_password == confirm_password:
                    registration_result = register_user(server_url, username, user_email, user_password)
                    print()
                    for key, value in registration_result:
                        print(f"{key} {value}")
                else:
                    print()
                    print("Passwords do not match!")
                print()    
            elif choice == "3":
                server_url = input("Please enter a new url: ")
            elif choice == "Q" or choice=="q":
                break
            else:
                print("Invalid choice")    
                
    #MENU SHOWING WHILE WE LOGGED IN OR AUTHENTICATED WITH TOKEN       
    if authenticated:        
        while True:
            username, email = get_account_info(server_url)#---Making current users username and email available to authenticated user
            friends = get_user_friends(server_url)
            
            print("\nMAIN MENU:")
            print()
            print("\nPlease choose an option:")
            print()
            print("1. TECHNICAL ACTIONS")
            print("2. ACCOUNT ACTIONS")
            print("3. LOG OUT")
            print("Q to exit")

            choice = input(">> ")
            
            if choice == "1":
                while True:
                    print("\TECHNICAL MENU:")
                    print()
                    print("\nPlease choose an option:")
                    print()
                    print("1. Get all users.")
                    print("2. Generate SSH Keypair and symmetrical key(needed to create and read messages/tweets)")
                    # print("3. Check public key)")
                    print("B to return to main menu")
                    
                    sub_choice = input(">> ")
                    
                    if sub_choice == "1":
                        all_users = get_all_users(server_url)
                        print()
                        print("---ALL USERS---")
                        print()
                        for user in all_users:
                            print(user)
                            print()
                    elif sub_choice == "2":
                        if detect_private_key() and detect_sym_key() and detect_public_key():
                            print()
                            print("Keys already exist, overwriting them will make your account irretrievable!!")
                            print()
                            print("Key creation canceled!")
                        else:    
                            public_key, private_key = generate_keypair()
                            save_private_key(private_key)
                            save_public_key(public_key)
                            symmetric_key = generate_sym_key()
                            upload_result = upload_keystore(server_url, public_key, symmetric_key)
                            print("------------------------")
                            print(upload_result)
                            print("------------------------")
                            
                    elif sub_choice == "B" or sub_choice=="b":
                        print("Returning to main menu...")
                        break        
                    else:
                        print("Invalid choice")        
            elif choice == "2":
                while True:
                    print("\nACCOUNT MENU:")
                    print()
                    print("\nPlease choose an option:")
                    print()
                    print("1. Check your account details")
                    print("--------------------------------")
                    print("2. Create a message")
                    print("3. Show all messages from a friend")
                    print("--------------------------------")
                    print("4. Add a friend")
                    print("5. Check friends list")
                    print("--------------------------------")
                    print("B to return to main menu")
                    
                    sub_choice = input(">> ")
                    
                    if sub_choice == "1":
                        print("---YOUR ACCOUNT DETAILS---")
                        print()
                        print(f"Username : {username}")
                        print(f"Email : {email}")
                    elif sub_choice == "2":
                        #---MESSAGE POSTING CODE---#                       
                        print()
                        print(f"POSTING AS >>  {username}")
                        print()
                        title = input("Please choose a title for your Thought: \n\n>>TITLE: ")                        
                        message = input("What would you like to post? : \n\nMESSAGE>>: ")
                        sym_key, enc_mess = encrypt_message_symmetrical(message)
                        print()
                        
                        post_thought(server_url, username, title, enc_mess)                         
                                     
                        print("Message uploaded successfully!")
                                            
                    elif sub_choice == "3":
                        get_user_friends(server_url)
                        print()
                        
                        base_64_encr_sym_key = None
                        friend_username = ''
                        #error handling of faulty passwords
                        while type(base_64_encr_sym_key) != str or friend_username == None:
                            user_password = getpass.getpass(prompt ="Please confirm your password to get your messages:  \n\n")
                            friend_username = input("Please enter the username of the friend that you want to see messages from: \n\n")
                            if friend_username == '':
                                print("You didn't provide a username for your friend!")
                            base_64_encr_sym_key = get_sym_key(server_url, user_password, friend_username)
                            
                            
                        encrypted_sym_key = base64.b64decode(base_64_encr_sym_key)
                                                
                        for thought in get_thoughts_for_user(server_url, friend_username):
                            print("-------------------------------------------------------")
                            print(f"TITLE:  {thought['title']}")
                            print()
                            print(f"RATING:  { thought['rating']}")
                            print()
                            decrypted_message = decrypt_message(thought["content"].encode("utf-8"), encrypted_sym_key)
                            print(f"MESSAGE:  { decrypted_message}")
                            print("-------------------------------------------------------")     
                            print()
                            
                    elif sub_choice == "4":
                        friend_username = input("Enter your friend's username:")
                        add_friend_result = add_user_friends(server_url, friend_username)
                        print("---------------------------")
                        print(f"Trying to add {friend_username} as a friend. RESULT : {add_friend_result}")
                        print("---------------------------")
                    elif sub_choice == "5":
                        print()
                        print("---Friends---")
                        print()
                        for friend in friends:
                            print(f"- {friend}")
                            print()
                    elif sub_choice == "B" or sub_choice=="b":
                        print("Returning to main menu...")
                        break        
                    else:
                        print("Invalid choice")
            elif choice == "3":
                log_out()
                authenticated == False
                break

                # file_path = "token.json"  
                # if os.path.exists(file_path):
                #     os.remove(file_path)
                #     print("Logged out successfully!")
                #     
                #     break
                # else:
                #     print("You are not logged in!")    
            elif choice == "Q" or choice=="q":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


