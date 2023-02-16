from Crypto.Util.number import *
from hashlib import sha256
import secrets

# Modular Multiplicative Inverse
def mod_inverse(a, m) : 
    a=a%m; 
    for x in range(1,m) : 
        if((a*x)%m==1) : 
            return(x) 
    return(1)

def parameter_generation():
    #important note: prime numbers keep your encrypted messages safe. The reason prime numbers are fundamental 
    # to RSA encryption is because when you multiply two together, the result is a number that can only be broken 
    # down into those primes (and itself an 1).

    q=getPrime(1024) #using a larger key size makes it more secure
    p=getPrime(2048) #using a larger key size makes it more secure

    while((p-1)%q!=0):
        p=getPrime(10)
        q=getPrime(5)
    print("q:",q)
    print("p:",p)
    flag=True
    while(flag):
        h=int(input("Enter integer between 1 and p-1(h): "))
        # h must be in between 1 and p-1
        if(1<h<(p-1)):
            g=1
            while(g==1):
                g=pow(h,int((p-1)/q))%p
            flag=False
        else:
            print("Incorrect entry")
    print("g:",g)
    return(p,q,g)

def per_user_key(p,q,g):
    # User private key:
    x = secrets.randbelow(q-1)
    print("Random private key(x): ",x)
    # User public key:
    y=pow(g,x)%p
    print("Random public key(y): ",y)
    return(x,y)

def signature(name,p,q,g,x):
    with open(name) as file:
        text=file.read()
        hash_component = sha256(text.encode("UTF-8")).hexdigest()
        print("Hash of document sent: ",hash_component)
    r,s=0,0
    while(s==0 or r==0):
        k = secrets.randbelow(q-1)
        r=((pow(g,k))%p)%q
        i=mod_inverse(k,q)
        # converting hexa decimal to binary
        hashed=int(hash_component,16)
        s=(i*(hashed+(x*r)))%q
    # returning the signature components
    return(r,s,k)

def verification(name,p,q,g,r,s,y):
    with open(name) as file:
        text=file.read()
        hash_component = sha256(text.encode("UTF-8")).hexdigest()
        print("Hash of document received: ",hash_component)
    w=mod_inverse(s,q)
    print("Value of w is : ",w)
    hashed=int(hash_component,16)
    u1=(hashed*w)%q 
    u2=(r*w)%q
    v=((pow(g,u1)*pow(y,u2))%p)%q
    print("u1: ",u1)
    print("u2: ",u2)
    print("v: ",v)
    if(v==r):
        print("The signature is valid!")
    else:
        print("The signature is invalid!")
global_var=parameter_generation()
keys=per_user_key(global_var[0],global_var[1],global_var[2])

# Sender's side (signing the document):
file_name=input("Name of document to sign: ")
components=signature(file_name,global_var[0],global_var[1],global_var[2],keys[0])
print("r(Component of signature):",components[0])
print("k(Random number):",components[2])
print("s(Component of signature):",components[1])

# Receiver's side (verifying the sign):
file_name=input("Enter the name of document to verify: ")
verification(file_name,global_var[0],global_var[1],global_var[2],components[0],components[1],keys[1])