from flask import Flask, render_template, request, redirect, abort
import time
from random import randrange

# username: [password, number of failed password attempts, secret]
users = {"user": ["user", 0, "my_secret"],
         "admin": ["admin", 0, "!t0ps3cr3t!"]}
app = Flask(__name__)

time_delay = 0.030

# For a login page there are four common states we would like to handle:
# success:  username and password are correct
# valid:    username is valid only
# invalid:  username is not valid
# locked: the account is locked

# UNIVERSAL FEATURES
random_length_variation = False
random_length_variation_max_amount = 19

# account lockout config
account_lockout = False
account_lockout_attempts = 5

status_based = True                   # 01 status code will change for valid username
time_based_valid_delay = False         # 02 time delay will occur on valid username, not on invalid username
time_based_invalid_delay = False       # 03 time delay will occur on invalid username, not on valid username
length_based_valid_longer = False      # 04 length will increase by 10 on valid username
length_based_valid_shorter = False     # 05 length will decrease by 10 on valid username
length_based_invalid_longer = False    # 06 length will increase by 10 on invalid username
length_based_invalid_shorter = False   # 07 length will decrease by 10 on invalid username
invalid_word_invalid = False           # 08 response will include the word invalid on invalid username
custom_word_invalid = False            # 09 response will include a custom word (BANANA) on invalid username
custom_word_valid = False              # 10 response will include a custom word (BANANA) on valid username
location_difference = False            # 11 return 302 redirect with different locations for valid and invalid usernames
length_based_success_longer = False    # 06 length will increase by 10 on invalid username
length_based_success_shorter = False   # 07 length will decrease by 10 on invalid username

def invalid_username():
    if status_based:
        return '!!!  INVALID USER  !!!', 404                        # 01
    if time_based_valid_delay:
        time.sleep(time_delay)
        return '!!!  INVALID USER  !!!', 200                        # 02
    if time_based_invalid_delay:
        return '!!!  INVALID USER  !!!', 200                        # 03
    if length_based_valid_longer:
        return '!!!  INVALID USER  !!!', 200                        # 04
    if length_based_valid_shorter:
        return '!!!  INVALID USER  !!!', 200                        # 05
    if length_based_invalid_longer:
        return '!!!  INVALID USER  !!!!!!  INVALID USER  !!!', 200   # 06
    if length_based_invalid_shorter:
        return 'E', 200                                            # 07
    if invalid_word_invalid:
        return 'ERROR INVALID USER  !!', 200                        # 08
    if custom_word_invalid:
        return '!!! INVALID BANANA !!!', 200                        # 09
    if custom_word_valid:
        return '!!!  INVALID USER  !!!', 200                        # 10
    if location_difference:
        return redirect('/invalidusername', code=302)       # 11
    if length_based_success_longer:
        return '!!!  INVALID USER  !!!', 200                        # 12
    if length_based_success_shorter:
        return '!!!  INVALID USER  !!!', 200                        # 13

def valid_username():
    if status_based:
        return '!!!  INVALID PASS  !!!', 404                        # 01
    if time_based_valid_delay:
        return '!!!  INVALID PASS  !!!', 200                        # 02
    if time_based_invalid_delay:
        time.sleep(time_delay)
        return '!!!  INVALID PASS  !!!', 200                        # 03
    if length_based_valid_longer:
        return '!!!  INVALID PASS  !!!!!!  INVALID PASS  !!!', 200   # 04
    if length_based_valid_shorter:
        return 'O', 200                                            # 05
    if length_based_invalid_longer:
        return '!!!  INVALID PASS  !!!', 200                        # 06
    if length_based_invalid_shorter:
        return '!!!  INVALID PASS  !!!', 200                        # 07
    if invalid_word_invalid:
        return 'ERROR INVALID PASS  !!', 200                        # 08
    if custom_word_invalid:
        return '!!! INVALID BANANA !!!', 200                        # 09
    if custom_word_valid:
        return '!!!  INVALID PASS  !!!', 200                        # 10
    if location_difference:
        return redirect('/validusername20', code=302)       # 11
    if length_based_success_longer:
        return '!!!  INVALID PASS  !!!', 200                        # 12
    if length_based_success_shorter:
        return '!!!  INVALID PASS  !!!', 200                        # 13

def account_locked():
    if status_based:
        return '!!! ACCOUNT LOCKED !!!', 403                        # 01
    if time_based_valid_delay:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 02
    if time_based_invalid_delay:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 03
    if length_based_valid_longer:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 04
    if length_based_valid_shorter:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 05
    if length_based_invalid_longer:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 06
    if length_based_invalid_shorter:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 07
    if invalid_word_invalid:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 08
    if custom_word_invalid:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 09
    if custom_word_valid:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 10
    if location_difference:
        return redirect('/accountlocked01', code=302)       # 11
    if length_based_success_longer:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 12
    if length_based_success_shorter:
        return '!!! ACCOUNT LOCKED !!!', 200                        # 13

def valid_username_and_password():
    if status_based:
        return '!!!! WELCOME USER !!!!', 200                        # 01
    if time_based_valid_delay:
        return '!!!! WELCOME USER !!!!', 200                        # 02
    if time_based_invalid_delay:
        return '!!!! WELCOME USER !!!!', 200                        # 03
    if length_based_valid_longer:
        return '!!!! WELCOME USER !!!!', 200                        # 04
    if length_based_valid_shorter:
        return '!!!! WELCOME USER !!!!', 200                        # 05
    if length_based_invalid_longer:
        return '!!!! WELCOME USER !!!!', 200                        # 06
    if length_based_invalid_shorter:
        return '!!!! WELCOME USER !!!!', 200                        # 07
    if invalid_word_invalid:
        return '!!!! WELCOME USER !!!!', 200                        # 08
    if custom_word_invalid:
        return '!!!! WELCOME USER !!!!', 200                        # 09
    if custom_word_valid:
        return '!!!! WELCOME USER !!!!', 200                        # 10
    if location_difference:
        return redirect('/homelandingpage', code=302)       # 11
    if length_based_success_longer:
        return '!!!! WELCOME USER !!!!!!!! WELCOME USER !!!!', 200                        # 12
    if length_based_success_shorter:
        return 'WE', 200                        # 13

def authentication_logic(username, password):
    for user in users:
        # user is authenticated
        if (user == username):
            if (users[user][0] == password):
                result = valid_username_and_password()
                return result
            else: # username is valid, but password is not
                attempts = users[user][1]
                if account_lockout: # increment failed attempts count
                    users[user][1] = attempts + 1
                if attempts > 4:
                    result = account_locked()
                else:
                    result = valid_username()
                if random_length_variation:
                    random_length = randrange(random_length_variation_max_amount)
                    rand_string = "_" * random_length
                    resulta, resultb = result
                    return resulta + rand_string, resultb
                else:
                    return result

    # username is not valid
    result = invalid_username()
    return result
@app.route("/")
def index():
    return render_template('index.html')

@app.route("/login", methods=['POST'])
def login():
    # Get the DATA from the login request:
    username = request.form["username"]
    password = request.form["password"]

    result = authentication_logic(username, password)
    return result


@app.route("/landing_json")
def landing_json():
    return render_template('landing_json.html')
@app.route("/login_json", methods=['POST'])
def login_json():
    request_data = request.get_json()

    username = request_data['username']
    password = request_data['password']

    result = authentication_logic(username, password)
    return result

@app.route("/validusername20")
def validusername20():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">

    <body>
    !!!! INVALID PASSWORD !!!!
    </body>
    </html>
    """
    return html

@app.route("/invalidusername")
def invalidusername():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">

    <body>
    !!!! INVALID USERNAME !!!!
    </body>
    </html>
    """
    return html

@app.route("/homelandingpage")
def homelandingpage():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    
    <body>
    !!!! WELCOME USER !!!!
    </body>
    </html>
    """
    return html


@app.route("/accountlocked01")
def accountlocked01():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">

    <body>
    !!! ACCOUNT LOCKED !!!
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=True, port=8989)

