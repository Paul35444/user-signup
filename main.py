#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
#import regex for user_name, password, and email verification
import re

form = """
<!DOCTYPE html>
    <head>
        <title>User-Signup</title>
        <style type= "text/css">
            .error {
                color: red;
            }
        </style>
    </head>
    <body>
    <h1>Signup</h1>
	<form method='post'>
		<label>Username: </label>
		<input type='text' name='username' value="%(username)s" required/>
		      <span class='error'>%(invalid_username)s</span><br><br>
		<label>Password:</label>
		      <input type='password' name='password' required/>
		            <span class='error'>%(invalid_password)s</span><br><br>
		<label>Verify Password:</label>
		      <input type='password' name='verify' required/>
		            <span class='error'>%(passwords_do_not_match)s</span><br><br>
		<label>Email (optional):</label>
		      <input type='text' name='email' value="%(email)s"/>
		            <span class='error'>%(invalid_email)s</span><br><br>
		<input type='submit'/>
	</form>
	</body>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #username requirements
def valid_username(username):
    return USER_RE.match(username) #check against requirements using re

PASSWORD_RE = re.compile(r"^.{3,20}$") #password requirements
def valid_password(password):
    return PASSWORD_RE.match(password) #check agianst requirements using re
def password_match(password, verify):
    return password == verify

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$") #email requirements
def valid_email(email):
    return EMAIL_RE.match(email) #check against requirements using re

#create a valid input
#use a dictionary
def valid_input(username, password, verify, email=""): #add all inputs

    valid_dictionary = {} #create a blank dictionary

    if valid_username(username) is None: #if username error create a response
        valid_dictionary["invalid_username"] = "That is not a valid username. Please do not use spaces."

    if valid_password(password) is None: #if password error create a response
        valid_dictionary["invalid_password"] = "That is not a valid password."

    if password_match(password,verify) == False: #if password and verify dont match create a response
        valid_dictionary["passwords_do_not_match"] = "The passwords entered do not match, please enter both again."

    if email != "":
        if valid_email(email) is None: #if email error create a response
            valid_dictionary["invalid_email"] = "This is not a valid email. Please follow the example. Example: email@somewhere.com"

    return valid_dictionary #return completed the dictionary



class MainHandler(webapp2.RequestHandler):
    def write_form(self, invalid_username="", invalid_password="",
            passwords_do_not_match="", invalid_email="", username="", email=""):
        self.response.write(form % {
                "invalid_username":invalid_username,
                "invalid_password":invalid_password,
                "passwords_do_not_match":passwords_do_not_match,
                "invalid_email":invalid_email,
                "username":username,"email":email})

    def get(self): #function to produce form
        self.write_form()

    def post(self): #function to post
        user_name = self.request.get("username")
        password = self.request.get("password")
        verify_password = self.request.get("verify")
        email = self.request.get("email")

        #collect the errors
        errors = valid_input(user_name, password, verify_password, email)

        if len(errors) > 0:
            errors["username"] = user_name
            errors["email"] = email
            self.write_form(**errors) #write the above collected errors
        else:
            self.redirect("/success?username=" + user_name)

class Success(webapp2.RequestHandler):
    def get(self):
        user_name = self.request.get("username")
        self.response.write("<h1>Successful Login, " + user_name + "!</h1>")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/success', Success)
], debug=True)
