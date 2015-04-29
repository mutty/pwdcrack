#!/usr/bin/python
# A not so efficient password cracker in python
# Methias Talamantes - CS 177

import crypt, sys, time, os

global user, hashp, salt, start_time

def main():
    global user, hashp, salt, dictionary
    os.system('clear')

    if len(sys.argv) != 3:
        print "Usage: ./pwdc.py shadow_file wordlist"
    else:
        # Print welcome message
        welcome()
        # Begin doing work
        shadowFile = open(sys.argv[1], 'r')
        dictionary = sys.argv[2]

        for line in shadowFile:
            splitLine = line.split(":")
            user = splitLine[0]
            hashp = splitLine[1]
            
            if "$" not in splitLine[1]:
                salt = splitLine[1][0:2]
            else:
                temp = splitLine[1].split("$")
                salt = "$" + temp[1] + "$" + temp[2]

            print "[*] Cracking " + user + "'s hash " + hashp + " with salt " + salt
            crack()
        
        print "[!] No hashes left, exiting..."
        shadowFile.close()
    
def crack():
    global user, hashp, salt
    password_found = False
    # First we try attacks based off the associated username
    # as this is the least expenisve attack vector
    if crackByUsername():
        return
    # Username attack failed, ask user if wish to try next attack
    if not check("dictionary"):
        # Skipping to next hash
        return
    if crackByDict():
        return
    if not check("basic num substitution"):
        return
    if crackByNumSub():
        return
    if not check("add numbers to the end"):
        return
    if crackByAddingNumbers():
        return

    # All attack vectors failed
    print "[*] Password not found. Moving on...\n"
    return

def crackByUsername():
    global user, hashp, salt, start_time
    start_time = time.time()
    print "[*] Guessing passwords based on username..."
    subbed_user = sub(user, False)
    subbed_user_obs = sub(user, True)
    if crypt.crypt(user, salt) == hashp:
        return password_found(user)
    # Try reverse
    if crypt.crypt(user[::-1], salt) == hashp:
        return password_found(user[::-1])
    if crypt.crypt(subbed_user, salt) == hashp:
        return password_found(subbed_user)
    # Try reverse
    if crypt.crypt(subbed_user[::-1], salt) == hashp:
        return password_found(subbed_user[::-1])
    if crypt.crypt(subbed_user_obs, salt) == hashp:
        return password_found(subbed_user_obs)
    # Try reverse
    if crypt.crypt(subbed_user_obs[::-1], salt) == hashp:
        return password_found(subbed_user_obs[::-1])
    # Try appending a single number
    for i in range(0, 10):
        if crypt.crypt(user + str(i), salt) == hashp:
            return password_found(user + str(i))
        # Try reverse
        if crypt.crypt(user[::-1] + str(i), salt) == hashp:
            return password_found(user[::-1] + str(i))
    # Try appending multiple numbers
    tmp_user = user + "1" # already tested user1 above
    tmp_userR = user[::-1] + "1" # reverse
    for i in range(2, 4):
        tmp_user = tmp_user + str(i)
        if crypt.crypt(tmp_user, salt) == hashp:
            return password_found(tmp_user)
        # Try reverse
        tmp_userR = tmp_userR + str(i)
        if crypt.crypt(tmp_userR, salt) == hashp:
            return password_found(tmp_user[::-1])
    # Attack via username failed
    return False

def crackByDict():
    global hashp, salt, dictionary
    wordlist = open(dictionary, 'r')

    print "[*] Trying dictionary attack..."
    for line in wordlist:
        if crypt.crypt(line.rstrip(), salt) == hashp:
            return password_found(line.rstrip())
        # Try reverse
        if crypt.crypt(line.rstrip()[::-1], salt) == hashp:
            return password_found(line.rstrip()[::-1])
    wordlist.close()
    # Dictionary attack failed
    return False

def crackByNumSub():
    global hashp, salt, dictionary
    wordlist = open(dictionary, 'r')
    print "[*] Trying basic num substitution..."
    for line in wordlist:
        line = sub(line, False)
        if crypt.crypt(line.rstrip(), salt) == hashp:
            return password_found(line.rstrip())
        else: # Try more obscure sub
            line = sub(wordlist, True)
            if crypt.crypt(line.rstrip(), salt) == hashp:
                return password_found(line.rstrip())
    wordlist.close()
    # Basic num sub attack failed
    return False 

def crackByAddingNumbers():
    global hashp, salt, dictionary
    wordlist = open(dictionary, 'r')
    print "[*] Adding numbers to the end of dictionary words..."
    for line in wordlist:
        # Append a single digit to the end
        for i in range(0, 10):
            if crypt.crypt((line + str(i)).rstrip(), salt) == hashp:
                return password_found(line + str(i))
            # Try reverse
            if crypt.crypt(line.rstrip()[::-1] + str(i), salt) == hashp:
                return password_found(line[::-1] + str(i))
        # Append multiple digits to the end
        line = line + "1" # already tried line1 above
        for i in range(2,4):
            line = line + str(i)
            if crypt.crypt(line.rstrip(), salt) == hashp:
                return password_found(line)
            # Try reverse
            if crypt.crypt(line.rstrip()[::-1], salt) == hashp:
                return password_found(line[::-1])
    wordlist.close()
    # Adding numbers attack failed
    return False

# Merely a helper function for crackByNumSub
def sub(line, obscure):
    if not obscure:
        line = str(line).replace("I", "1")
        line = line.replace("i", "1")
        line = line.replace("E", "3")
        line = line.replace("e", "3")
        line = line.replace("A", "4")
        line = line.replace("a", "4")
        line = line.replace("S", "5")
        line = line.replace("s", "5")
        line = line.replace("O", "0")
        line = line.replace("o", "0")

    else:
        line = str(line).replace("I", "1")
        line = line.replace("i", "!")
        line = line.replace("E", "3")
        line = line.replace("e", "3")
        line = line.replace("A", "4")
        line = line.replace("a", "@")
        line = line.replace("S", "5")
        line = line.replace("s", "5")
        line = line.replace("O", "0")
        line = line.replace("o", "0")
        line = line.replace("b", "6")
        line = line.replace("B", "8")
        line = line.replace("t", "7")
        line = line.replace("T", "7")
        lien = line.replace("l", "1")
    
    return line

def password_found(password):
    global start_time
    stop_time = time.time()
    print "[!] Password found: " + password 
    print "[!] Total elapsed time: " + '{:.2}'.format(stop_time - start_time) + "s\n"
    return True

def check(attack):
    sys.stdout.write('[*] Pwd not found, try ' + attack +
                     ' attack, skip, or quit [t/s/q]? ')
    answer = raw_input()
    if answer == "t":
        return True
    if answer == "s":
        print "[*] Password not found, skipping...\n"
        return False
    if answer == "q":
        exit()

def exit():
    print "[*] Quitting..."
    sys.exit(1)

def welcome():
    sys.stdout.write( '-----------------------------------------------\n' +
                      '|              let\'s get crackin\'             |\n' +
                      '|                                             |\n' +
                      '-----------------------------------------------\n\n')

# Begin program
main()

