import requests
import hashlib
import sys


def request_api_data(query):
    # take hash password and request api to the list of passwords 
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Exception finding {res.status_code}')
    return res

def get_pass_count(hashes,hash_to_check):
    #take hashes and hash to check and compare them
    list_hashes = hashes.text.splitlines()
    #split tail hashes and its counts into a tuple
    hashes = (line.split(':') for line in list_hashes)
    # print(hashes)
    for h,count in hashes:
        if(h == hash_to_check):
            return count
    return 0

def pwned_api_pass(password):
    # take password and convert it in hashes
    
    pwd = password.encode('utf-8') 
    sha1_hash = hashlib.sha1(pwd).hexdigest().upper() # converting password into SHA_hash hexadecimal code
    first5_char,tail = sha1_hash[:5],sha1_hash[5:]
    response = request_api_data(first5_char)

    return get_pass_count(response,tail)




def main(pass_file):
    with open(pass_file,'r') as file:
      passwords_list = list(file)
    for password in passwords_list:
        if(password[-1] == '\n'):  
            password = password[:-1]
        count = pwned_api_pass(password)   
        if count:
            print(f'{password} was found {count} times, You should probably Change your Password...')
        else:
            print(f'{password} was NOT found, Carry On !!!..') 

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
