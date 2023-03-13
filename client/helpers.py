#---WELCOME SCREEN---#

welcome_label_helper = """
MDLabel: 
    text: "Welcome to the alpha version of the Peerbrain application!"
    pos_hint: {"center_x" : 0.7,"center_y":0.9}                        
    theme_text_color: "Custom"
    text_color: (0,1,0, 1)
    font_style: "H6"
"""

login_icon_helper = """
MDIcon: 
    icon: "account-multiple" 
    pos_hint: {"center_x" : 0.4,"center_y":0.65}
"""

login_button_helper = """
MDRectangleFlatButton:
    text: "Log In" 
    pos_hint: {"center_x" : 0.5,"center_y":0.65}
    #on_release : app.log_in_screen()
"""

create_user_icon_helper = """
MDIcon: 
    icon: "account-plus" 
    pos_hint: {"center_x" : 0.4,"center_y":0.55}
"""

create_user_button_helper = """
MDRectangleFlatButton: 
    text: "Create User" 
    pos_hint: {"center_x" : 0.5,"center_y":0.55}
    #on_release : app.create_user_screen()
"""

change_server_icon_helper = """
MDIcon: 
    icon: "server-plus"
    pos_hint: {"center_x" : 0.4,"center_y":0.45}
"""

change_server_button_helper = """
MDRectangleFlatButton: 
    text: "Change Server" 
    pos_hint: {"center_x" : 0.5,"center_y":0.45}
    on_release : app.change_server_screen()
"""

close_button_icon_helper = """ 
MDFloatingActionButton:
    icon: "close-circle"
    pos_hint: {"center_x" : 0.5,"center_y":0.15}
    on_release : app.close_app()
""" 

#---LOGIN SCREEN---#

username_helper = """
MDTextField:
    hint_text: "Enter username"
    #helper_text: "Or click forgot Username"
    helper_text_mode: "on_focus"
    icon_left: "account"
    icon_left_color: app.theme_cls.primary_color
    pos_hint: {"center_x" : 0.5,"center_y":0.6}
    size_hint_x: None 
    width: 300
"""

password_helper = """
MDTextField:
    hint_text: "Enter password"
    #helper_text: "Or click forgot Password"
    helper_text_mode: "on_focus"
    password: True
    icon_left: "lock"
    icon_left_color: app.theme_cls.primary_color
    pos_hint: {"center_x" : 0.5,"center_y":0.4}
    size_hint_x: None 
    width: 300
"""

login_to_server_button_helper = """
MDRectangleFlatButton: 
    text: "Log In" 
    pos_hint: {"center_x" : 0.5,"center_y":0.3}
    on_release : app.log_in()
"""

back_to_welcome_button_helper = """
MDRectangleFlatButton: 
    text: "Back" 
    pos_hint: {"center_x" : 0.5,"center_y":0.2}
    
"""
#---CREATE USER---#
new_username_helper = """
MDTextField:
    hint_text: "Enter username"
    icon_left: "account-plus"
    icon_left_color: app.theme_cls.primary_color
    pos_hint: {"center_x" : 0.5,"center_y":0.7}
    size_hint_x: None 
    width: 300
"""

new_password_helper = """
MDTextField:
    hint_text: "Enter password"
    password: True
    icon_left: "lock-plus"
    icon_left_color: app.theme_cls.primary_color
    pos_hint: {"center_x" : 0.5,"center_y":0.6}
    size_hint_x: None 
    width: 300
"""

confirm_new_password_helper = """
MDTextField:
    hint_text: "Confirm password"
    password: True
    icon_left_color: app.theme_cls.primary_color
    pos_hint: {"center_x" : 0.5,"center_y":0.5}
    size_hint_x: None 
    width: 300
"""

create_new_user_button_helper = """
MDRectangleFlatButton: 
    text: "Create User" 
    pos_hint: {"center_x" : 0.5,"center_y":0.4}
    """

back_to_welcome_button_helper2 = """
MDRectangleFlatButton: 
    text: "Back" 
    pos_hint: {"center_x" : 0.5,"center_y":0.2}
    """
#---CHANGE SERVER DIALOG---#

change_server_confirmation_button_helper = """
MDRectangleFlatButton: 
    text: "Confirm Server Change" 
"""

change_server_close_button_helper = """
MDRectangleFlatButton: 
    text: "Close"
    on_release: app.close_dialog() 
"""

change_server_textfield = """
MDTextField:
    id: server_textfield
    hint_text: "Enter new server"
"""

#---MAIN MENU SCREEN---#

main_menu_label_helper = """
MDLabel: 
    text: "MAIN MENU:"
    pos_hint: {"center_x" : 0.7,"center_y":0.9}                        
    theme_text_color: "Custom"
    text_color: (0,1,0, 1)
    font_style: "H6"
"""

technical_menu_button_helper = """
MDRectangleFlatButton:
    text: "Technical Menu" 
    pos_hint: {"center_x" : 0.5,"center_y":0.65}
    #on_release : app.log_in_screen()
"""

user_account_button_helper = """
MDRectangleFlatButton: 
    text: "User Actions" 
    pos_hint: {"center_x" : 0.5,"center_y":0.55}
    #on_release : app.create_user_screen()
"""

logout_button_helper = """
MDRectangleFlatButton: 
    text: "Log Out" 
    pos_hint: {"center_x" : 0.5,"center_y":0.45}
    on_release : app.log_out_from_main_menu()
"""


#---TECHNICAL MENU SCREEN---#

technical_menu_label_helper = """
MDLabel: 
    text: "TECHNICAL MENU:"
    pos_hint: {"center_x" : 0.7,"center_y":0.9}                        
    theme_text_color: "Custom"
    text_color: (0,1,0, 1)
    font_style: "H6"
"""

technical_menu_check_users_button_helper = """
MDRectangleFlatButton:
    text: "Show all users" 
    pos_hint: {"center_x" : 0.5,"center_y":0.65}
    #on_release : app.log_in_screen()
"""

technical_menu_generate_keys_button_helper = """
MDRectangleFlatButton: 
    text: "Generate keys" 
    pos_hint: {"center_x" : 0.5,"center_y":0.55}
    #on_release : app.create_user_screen()
"""

technical_menu_back_button_helper = """
MDRectangleFlatButton: 
    text: "Back to Main Menu" 
    pos_hint: {"center_x" : 0.5,"center_y":0.45}
"""