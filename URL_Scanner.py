from bs4 import BeautifulSoup
import re
import urllib.request
import time
import requests
import argparse
import imgkit

def vt_scan(apikey, inspecturl):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': inspecturl}
    response = requests.get(url, params=params)
    return response.json()

def analyze(url, apikey):
    try:
        f = open("whitelist.txt", "r").readlines()
    except FileNotFoundError as e:
     print(e.strerror)
    result = str(vt_scan(apikey, url))
    result = result[result.find("'positives': "):]
    result = result[result.find(" ") + 1:result.find(",")]
    print(url)
    try:
        if int(result) >= 2:
            print("Alert!!")
            if url+'\n' in f:
                imgkit.from_url(url, url[url.find(".")+1:url.find(".net")] + ".jpg", config = config)
            return 1
        print("Safe")
        return 0
    except ValueError:
        print("Invalid 'positives' value in: " + url)

def get_URL(url):
    u = urllib.request.urlopen(url)
    x = u.read()
    soup = BeautifulSoup(x, 'html.parser')
    strHTML = str(soup.encode("UTF-8"))
    open("out.html", "w", encoding="UTF-8").write(strHTML)
    pattern = re.compile("(http)s?\:\/\/([a-z]\.)?([a-z,0-9,.,-]+)")
    matches = pattern.finditer(strHTML)
    urles = set({})
    for match in matches:
        if match.group(0) not in urles:
            urles.add(match.group(0))
    f = open('out.html', 'w')
    f.write(str(soup.encode("UTF-8")))
    return urles

def main(user):
    i = 1
    key_num = 0
    while True:
        try:
            vt_apikey_list = ["9844f1d2fd86742ad1619853e3a63a5e53e13fe16d20baaa25727b9984971ae4",
                              "84fcec0f6e02409412ef4aeb18a9663edb57b3ec6ed76c25a53fafcb7fb8751f",
                              "cc5c358f233ad39230646152c373544d305b890e9e22e64515882ae85bd9c4bf",
                              "25a2f6199e30e955631446437c4b89fa932bfad6c2af4f68a9466a5b7ab3aae5",
                              "d71b2292f2c249e6f8a0e3082d1993be5fd055d95ddaa685ed890337d1d66089",
                              "3ad3b6cab3a83051345dd542cd5821d42ddf051b20d656ee3ac19efd6f7dcf56",
                              "a2546db760322cc041b1bece6524947a3360900976ad56ec567eebfaff8b0e75",
                              "65f2ec8fa98321e1943b49e26e8a20137c80333ef85022760f89d14d135b2bed"]

            try:
                url_list = {user}.union(get_URL(user))

                if user != url_list:
                    for url in url_list:
                        if analyze(url, vt_apikey_list[key_num]):
                            open("blacklist.txt", "a").write(url + "\n")
                        else:
                            open("whitelist.txt", "a").write(url + "\n")
                        if i % 4 == 0:
                            key_num = key_num + 1
                        if i % 4 == 0 and key_num == 7:
                            starttime = time.time()
                            print("Pausing for 90 sec")
                            time.sleep(90.0 - ((time.time() - starttime) % 90.0))
                            print("Resuming")
                            key_num = 0
                        i += 1
            except ValueError:
                print("Unknown Url type " + " " + user)
        except urllib.error.URLError:
            print("Couldn't open url and unknown url type " + "  " + user)


parser = argparse.ArgumentParser(description="URL Checking")
parser.add_argument("-u", "--url", type=str, required=True, help="URL for checking")
args = parser.parse_args()

starttime = time.time()

main(str(args.__getattribute__("url")))
