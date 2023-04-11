"""Brainwaves cli client file"""
import getpass
import base64
import json
import argparse
import os
import webbrowser

from encrypt_data import (
    generate_keypair,
    detect_private_key,
    save_private_key,
    encrypt_message_symmetrical,
    decrypt_message,
    generate_sym_key,
    detect_sym_key,
    detect_public_key,
    save_public_key,
)


from client_functions import (
    create_token, 
    get_token,
    get_account_info,
    get_sym_key,
    post_thought,
    register_user,
    add_user_friends,
    get_user_friends,
    get_all_users,
    get_thoughts_for_user,
    wrap_encrypt_sym_key,
    upload_keystore,
    login_with_token,
    log_out,
    reset_password,
    check_token, 
    remove_user_friends,
    update_rating_for_thought,
    get_user_conversation,
    post_conversation_message
)

from fastapi import HTTPException

def main():
    """Display the main menu and prompt the user to choose an option."""    
    # python cli_main.py -s dev FOR DEV SERVER OR python cli_main.py FOR NORMAL USE
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-s", "--server", help="Dev or live server", type=str, default="live")
    args = argParser.parse_args()
    if args.server == "dev":
        server_url = "http://127.0.0.1:8000/"
    else:
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
            print("1. Log in to the current server")
            print("2. Register account on the current server")
            print("3. Change server")
            print("4. Reset your password")
            print("Q to exit")
            choice = input(">> ")
            
            if choice == "1":
                
                try:
                    if check_token(server_url):
                        authenticated = True
                    elif login_with_token(server_url):
                        authenticated = True
                    else:
                        print("---")
                        print("Inactive user!")
                        print("---")
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
                    registration_result = register_user(server_url, username.lower(), user_email, user_password)
                    print()
                    for key, value in registration_result:
                        print(f"{key} {value}")
                else:
                    print()
                    print("Passwords do not match!")
                print()    
            elif choice == "3":
                server_url = input("Please enter a new url: ")
            elif choice == "4":
                print()
                password_reset_username = input("Please enter your username: ")
                print()
                reset_password(server_url, password_reset_username)
                print()
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
                    print("1. Generate SSH Keypair and symmetrical key(needed to create and read messages/tweets)")
                    print("B to return to main menu")
                    
                    sub_choice = input(">> ")
                    
                    # if sub_choice == "1":
                    #     all_users = get_all_users(server_url)
                    #     print()
                    #     print("---ALL USERS---")
                    #     print()
                    #     for user in all_users:
                    #         print(user)
                    #         print()
                    if sub_choice == "1":
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
                #temp storage of the password
                user_password=""
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
                    print("6. Remove a friend from your friend list")
                    print("--------------------------------")
                    print("7. View your messages singularly.")
                    print("8. Private conversations(DM)")
                    print("9. Enable 2FA")
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
                        
                        base_64_encr_sym_key = bytes(0)
                        friend_username = str()
                        #error handling of faulty passwords
                        try:
                            while friend_username == str() and isinstance(base_64_encr_sym_key, bytes):
                                user_password = getpass.getpass(prompt ="Please confirm your password to get your messages:  \n\n")
                                friend_username = input("Please enter the username of the friend that you want to see messages from: \n\n")
                                while friend_username == "":
                                    print("You didn't provide a username for your friend!\n\n")
                                    friend_username = str()
                                    friend_username += input("Please enter the username of the friend that you want to see messages from: \n\n")
                                
                                base_64_encr_sym_key = get_sym_key(server_url, user_password, friend_username)
                            try:
                                encrypted_sym_key = base64.b64decode(base_64_encr_sym_key)
                                                
                                for thought in get_thoughts_for_user(server_url, friend_username):
                                    print("-------------------------------------------------------")
                                    print(f"TITLE:  {thought['title']}")
                                    print()
                                    print(f"RATING:  { thought['rating']}")
                                    print()
                                    try:
                                        decrypted_message = decrypt_message(thought["content"].encode("utf-8"), encrypted_sym_key)
                                        print(f"MESSAGE:  { decrypted_message}")
                                    except FileNotFoundError as err:
                                        print("Error decrypting message, you may need to generate your keys still!\nError:", err)
                                    except ValueError as err:
                                        print("Please restart the programme to register your keys!\nError:", err)
                                        break
                            except TypeError as err:
                                print("Error decrypting the symmetrical key, you may need to generate your keys still, or your password was incorrect!\nError:", err)
                        except json.decoder.JSONDecodeError as err:
                            print("Error decoding the symmetrical key, you may need to generate your keys still!\n Error:", err) 
                        print("-------------------------------------------------------")     
                        print()
                    elif sub_choice == "4":
                        friend_username = input("Enter your friend's username:")
                        add_friend_result = add_user_friends(server_url, friend_username)
                        print("---------------------------")
                        print(f"Trying to add {friend_username} as a friend. RESULT : {add_friend_result}")
                        print("---------------------------")
                        #reloading friends object after adding a friend
                        friends = get_user_friends(server_url)
                    elif sub_choice == "5":
                        print()
                        print("---Friends---")
                        print()
                        for friend in friends:
                            print(f"- {friend[0]}")
                            print()
                    elif sub_choice == "6":
                        print()
                        print("---Friends---")
                        print()
                        for friend in friends:
                            print(f"- {friend[0]}")
                            print()
                        friend_username = input("Enter the username of the friend you want to remove:")
                        print()
                        remove_user_friends(server_url, friend_username)
                        #reloading friends object after removing a friend
                        friends = get_user_friends(server_url)
                    elif sub_choice == "7":
                        get_user_friends(server_url)
                        print()
                        
                        base_64_encr_sym_key = bytes(0)
                        friend_username = str()
                        
                        #error handling of faulty passwords
                        
                        while friend_username == str() and isinstance(base_64_encr_sym_key, bytes):
                            if user_password == "":
                                user_password = getpass.getpass(prompt ="Please confirm your password to get your messages:\n\n")
                            friend_username = input("Please enter the username of the friend that you want to see messages from:\n\n")
                            while friend_username == "":
                                print("You didn't provide a username for your friend!\n\n")
                                friend_username = str()
                                friend_username += input("Please enter the username of the friend that you want to see messages from:\n\n")
                            
                            base_64_encr_sym_key = get_sym_key(server_url, user_password, friend_username)
                            
                            encrypted_sym_key = base64.b64decode(base_64_encr_sym_key)
                            thoughts = get_thoughts_for_user(server_url, friend_username)
                            reading = True
                            if len(thoughts) == 0:
                                print("No thoughts found for this user.")
                            else:
                                while reading:
                                    print("Please choose a thought to read by entering its number or type B to go back:\n")
                                    i = 0
                                    for thought in thoughts:
                                        print(f"{i + 1}. TITLE: {thought['title']}\t RATING: {thought['rating']}")
                                        i += 1
                                    try:
                                        thought_choice = input("\nEnter thought number: ")
                                        if thought_choice == "b" or thought_choice == "B":
                                            reading = False
                                        else:
                                            thought_num = int(thought_choice)
                                            selected_thought = thoughts[thought_num - 1]
                                            print(f"\nTITLE:  {selected_thought['title']}")
                                            print(f"RATING: {selected_thought['rating']}\n")
                                            decrypted_message = decrypt_message(selected_thought['content'], encrypted_sym_key)
                                            print(f"MESSAGE:  {decrypted_message}\n\n")
                                            key_path = os.path.join(os.path.dirname(__file__), 'keys', 'message.key')
                                            with open(key_path, 'rb') as key_file:
                                                key = str(key_file.read())
                                            update_rating_for_thought(server_url, key)
                                            finished_reading = input("B: Finished reading ")
                                            if finished_reading == "b" or finished_reading == "B":
                                                reading = False
                                    except FileNotFoundError as err:
                                        print("Error decrypting message, you may need to generate your keys still!\nError:", err)
                                    except ValueError as err:
                                        print("Please restart the programme to register your keys!\nError:", err)
                                    except IndexError as err:
                                        print("You selected a non-existant thought number.\nError:", err)
                    elif sub_choice == "8":
                        friend_username = input("Please enter your friends username: \n")
                        get_user_conversation(server_url, friend_username)
                        print()
                        message = str()
                        print("1. Yes")
                        print("2. No")
                        choice = int(input(f"Do you want to reply to {friend_username}? "))
                        if choice == 1:
                            message += str(input("Enter your message: "))
                        post_conversation_message(server_url, friend_username, message)
                        print()
                    elif sub_choice == "9":
                        print("Launching 2FA setup in browser...")
                        token = get_token()
                        mfa = "https://mfa.peerbrain.net"
                        mfaurl = f"{mfa}/?token={token}&username={username}"
                        webbrowser.open(mfaurl)    
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


