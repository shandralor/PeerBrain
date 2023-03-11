from kivymd.app import MDApp
from kivymd.uix.screen import Screen
from kivymd.uix.screenmanager import ScreenManager
from kivymd.uix.dialog import MDDialog
from kivy.lang import Builder
from kivy.properties import StringProperty
from kivymd.uix.label import MDLabel
import os
import requests

from helpers import welcome_label_helper, login_icon_helper, login_button_helper, create_user_icon_helper, \
    create_user_button_helper, change_server_icon_helper, change_server_button_helper, close_button_icon_helper, \
        username_helper, password_helper, login_to_server_button_helper, change_server_confirmation_button_helper, \
            change_server_textfield, change_server_close_button_helper, back_to_welcome_button_helper, \
                new_password_helper, new_username_helper, confirm_new_password_helper, create_new_user_button_helper, \
                    back_to_welcome_button_helper2

from cli_main import create_token, get_token

class PeerbrainApp(MDApp):
    
    server_url = StringProperty('https://peerbrain.teckhawk.be/')
               
    def build(self):
        
        self.theme_cls.primary_palette = "Green"
        self.theme_cls.theme_style="Light"
        screen_manager = ScreenManager()
         
        #----------------------------------------------------------------#
        welcome_screen = Screen(name = "welcome")
        #----------------------------------------------------------------#
        welcome_label = Builder.load_string(welcome_label_helper)
        self.server_label = MDLabel(text=self.server_url,
                                    size_hint_x=None,
                                    width=280, 
                                    pos_hint= {"center_x": 0.5, "center_y": 0.8},
                                    theme_text_color= "Secondary",
                                    text_color= (0,1,0, 1),
                                    font_style= "H6")
        login_icon = Builder.load_string(login_icon_helper)
        login_button = Builder.load_string(login_button_helper)
        create_user_icon = Builder.load_string(create_user_icon_helper)
        create_user_button = Builder.load_string(create_user_button_helper)
        change_server_icon = Builder.load_string(change_server_icon_helper)
        change_server_button = Builder.load_string(change_server_button_helper)
        close_button_icon = Builder.load_string(close_button_icon_helper)
        
        welcome_screen.add_widget(welcome_label)
        welcome_screen.add_widget(self.server_label)
        welcome_screen.add_widget(login_icon)
        welcome_screen.add_widget(login_button)
        welcome_screen.add_widget(create_user_icon)
        welcome_screen.add_widget(create_user_button)
        welcome_screen.add_widget(change_server_icon)
        welcome_screen.add_widget(change_server_button)
        welcome_screen.add_widget(close_button_icon)
        
        screen_manager.add_widget(welcome_screen)
        
        #----------------------------------------------------------------#
        login_screen = Screen(name = "login")
        #----------------------------------------------------------------#        
        self.username_field = Builder.load_string(username_helper)
        self.password_field = Builder.load_string(password_helper)
        log_into_server = Builder.load_string(login_to_server_button_helper)
        back_to_welcome = Builder.load_string(back_to_welcome_button_helper) 
        
        login_screen.add_widget(self.username_field)
        login_screen.add_widget(self.password_field)
        login_screen.add_widget(log_into_server)
        login_screen.add_widget(back_to_welcome)
                
        screen_manager.add_widget(login_screen)
                
        # ----------------------------------------------------------------#
        create_user_screen = Screen(name = "create_user")
        # #----------------------------------------------------------------#
        self.new_username_field = Builder.load_string(new_username_helper)
        self.new_password_field = Builder.load_string(new_password_helper)
        self.confirm_new_password_field = Builder.load_string(confirm_new_password_helper)
        create_new_user_button = Builder.load_string(create_new_user_button_helper)
        back_to_welcome2 = Builder.load_string(back_to_welcome_button_helper2)
        
        create_user_screen.add_widget(self.new_username_field)
        create_user_screen.add_widget(self.new_password_field)
        create_user_screen.add_widget(self.confirm_new_password_field)
        create_user_screen.add_widget(create_new_user_button)
        create_user_screen.add_widget(back_to_welcome2)
        
        screen_manager.add_widget(create_user_screen)
        
        #================================================================#
        screen_manager.current = "welcome"
        
        def switch_to_welcome_screen():
            screen_manager.current = 'welcome'
        
        def switch_to_login_screen():
            screen_manager.current = 'login'
            
        def switch_to_create_user_screen():
            screen_manager.current = 'create_user'    
            
        login_button.on_release = switch_to_login_screen
        back_to_welcome.on_release = switch_to_welcome_screen
        back_to_welcome2.on_release = switch_to_welcome_screen
        create_user_button.on_release = switch_to_create_user_screen
        
        return screen_manager
        
        
       
    def change_server_screen(self):
        server_textfield = Builder.load_string(change_server_textfield)
        confirm_button = Builder.load_string(change_server_confirmation_button_helper)
        close_button = Builder.load_string(change_server_close_button_helper)
        self.dialog = MDDialog(title = "CHANGE SERVER", 
                          size_hint = (0.5, 1),
                          buttons = [ close_button, confirm_button])
        self.dialog.add_widget(server_textfield)
        
        def change_server_url():
            print(self.server_url)
            self.server_url = server_textfield.text
            self.server_label.text = self.server_url
            print(self.server_url)
            self.dialog.dismiss()
        
        confirm_button.on_release = change_server_url
        self.dialog.open()
    
       
    def close_app(self):
        self.stop()
        
    #--LOGIN SCREEN---#
    def log_in(self):
        username = self.username_field.text
        password = self.password_field.text
        print(username, password)
               
        
        
    #---CHANGE SERVER DIALOG---#
    def close_dialog(self):
        self.dialog.dismiss()
        
   
          
PeerbrainApp().run()



#Choosing custom colors is rgb values / 255 for each value