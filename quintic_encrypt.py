#!/usr/bin/env python
#-*- coding:utf-8 -*-

from subprocess import Popen, PIPE
from hashlib import sha512
from random import sample, randint
from struct import pack, unpack
import re

MAXIMA_EXEC = ["/Applications/Maxima.app/Contents/Resources/maxima/bin/sbcl",
               "--core",
               "/Applications/Maxima.app/Contents/Resources/maxima/lib/maxima/5.28.0/binary-sbcl/maxima.core",
               "--noinform", "--end-runtime-options", "--eval", "(cl-user::run)", "--end-toplevel-options",
               "-q", "--disable-readline",] # "--batch-string="
# mode to crack
SAME_KEY = 0
SAME_PLAIN = 1

# regular expressions for Maxima output 
COMPLEX_RE = re.compile(r"(?P<sign1>[-]?)(?P<imgnum>\d+)[*]%i(?P<sign2>[+\-])(?P<realnum>\d+)")
COMPLEX_RE2 = re.compile(r"(?P<sign2>[-]?)(?P<realnum>\d+)(?P<sign1>[+\-])(?P<imgnum>\d+)[*]%i")


class HighPowered(object):
    def __init__(self, debug=False, param_chars=5, num_of_keys=2):
        self.debug = debug
        self.quiet = False
        # each solution parameter contains plain data(self.param_chars byte) and order number(8bit)
        # so, if self.param_chars=5, it can be 0xFFFFFFFFFFF = 17592186044415 at most
        self.param_chars = param_chars
        self.num_of_keys = num_of_keys # encrypted equation will be (4+self.num_of_keys)-dimensional

    # Maxima batch string
    def EXPAND_POLY(self):
        return "display2d:false$linel:1000000$" +\
            "poly:expand((x-(%+d%+d*%%i))*(x-(%+d%+d*%%i))*(x-(%+d%+d*%%i))*(x-(%+d%+d*%%i))" + "*(x-(%+d%+d*%%i))"*self.num_of_keys + ")$\n" +\
            "[" + ",".join(["ratsimp(coeff(poly, x, %d))"%i for i in xrange(4+self.num_of_keys-1, -1, -1)]) + "];" # to encrypt
    def SOLVE_QUARTIC(self):
        return "display2d:false$linel:1000000$" +\
            "quartic:divide(x^%d" % (4+self.num_of_keys) + "".join(["+(%+d%+d*%%i)*x^"+"%d"%i for i in xrange(4+self.num_of_keys-1, -1, -1)]) + ", " + "*".join(["(x-(%+d%+d*%%i))" for i in xrange(self.num_of_keys)]) + ")$\n" +\
            "if quartic[2]#0 then print(\"ERROR!\") else solve(gfactor(quartic[1]));" # to decrypt with key
    def SOLVE_HIGH(self):
        return "display2d:false$linel:1000000$" +\
            "solve(gfactor(x^%d" % (4+self.num_of_keys) + "".join(["+(%+d%+d*%%i)*x^"+"%d"%i for i in xrange(4+self.num_of_keys-1, -1, -1)]) + "));"

    def junk(self, length):
        junk = ""
        for i in xrange(length):
            junk += chr(randint(0, 255))
        if self.debug:
            print "[*]junk:", "".join([hex(ord(c))[2:] for c in junk])
        return junk

    def encrypt(self, plaindata, key):
        # key : str
        # plaindata : data to encrypt
        org_length = len(plaindata)
        plaindata = plaindata + self.junk(self.param_chars*8 - len(plaindata) % (self.param_chars*8))
        
        # create equations regarding data/key as solution parameters
        sol_params = []
        # data to params
        for i,c in enumerate(plaindata):
            if i % (8*self.param_chars) == 0: # new equation
                sol_params.append([j for j in xrange(8)])
            sol_params[-1][(i%(self.param_chars*8))/self.param_chars] += ord(c)*0x100 ** (self.param_chars - (i % self.param_chars) - 1) * 0x10

        # shuffle params list => 8!(=479001600) patterns
        sol_params = [sample(param, 8) for param in sol_params]
        # key to params
        keyhash = sha512(key).hexdigest()
        if not self.quiet: print "[*] keyhash:", keyhash
        while len(keyhash) < self.param_chars * self.num_of_keys * 2 * 2:
            keyhash += sha512(keyhash).hexdigest()
            if not self.quiet: print "[*] keyhash:", keyhash
        for i in xrange(len(sol_params)):
            for k in xrange(self.num_of_keys*2): # in each equation
                sol_params[i].append(int(keyhash[self.param_chars*2*k:self.param_chars*2*(k+1)], 16)*0x10 + (k % 8))
        
        # check plus or minus
        for i in xrange(len(sol_params)):
            for j in xrange(8+self.num_of_keys*2):
                if sol_params[i][j] >> 39:
                    sol_params[i][j] = -sol_params[i][j]
        if not self.quiet:
            print "[*] sol_params(hex): [" + ", ".join(["["+", ".join([hex(c) for c in param])+"]" for param in sol_params]) + "]"
            #print "[*] sol_params(deci):", sol_params
        
        # calc coefficients of the equations
        coefficients = []
        for param in sol_params:
            coefficients.append([])
            output = self.run_maxima(self.EXPAND_POLY() % tuple(param))
            coeff_str_list = output.split("(%o4)")[-1].strip()[1:-1].split(",")
            for coeff_str in coeff_str_list:
                r = COMPLEX_RE.match(coeff_str.strip())
                if not r:
                    r = COMPLEX_RE2.match(coeff_str.strip())
                    if not r:
                        print "[!]", coeff_str.strip(), r
                        raise TypeError, "regular expression unmatch"
                coefficients[-1].append(int(r.group("sign2")+r.group("realnum")))
                coefficients[-1].append(int(r.group("sign1")+r.group("imgnum")))

        encdata = pack("<IH", org_length, self.param_chars) # length of original data
        for coeffs in coefficients:
            equ_header = pack("<H", len(coeffs)/2) # dimension of the equation
            equ_body = ""
            cur = 0
            for coeff in coeffs:
                equ_body += self.int2bin(coeff) # coefficient
                equ_header += pack("<I", len(equ_body) - cur) # length of int2bin(coefficient)
                cur = len(equ_body)
            encdata += (equ_header + equ_body)
        return encdata

    def encrypt_with_file(self, plaindata=None, plainfile=None, keydata=None, keyfile=None, encfile=None):
        # plainfile : str of file path to encrypt -> plaindata
        # keyfile : str of file path to use as key to encrypt -> keydata
        # encfile : str of file path to save the encrypted data

        if not self.quiet:
            print 
            print "< ENCRYPT MODE >"

        if not plaindata and plainfile:
            if not self.quiet: print "[*] plainfile: %s" % plainfile
            fd = open(plainfile, "rb")
            plaindata = fd.read()
            fd.close()
        elif plaindata:
            if not self.quiet: print "[*] plain data: %s" % plaindata
        else:
            raise AssertionError, "plaindata or plainfile required"

        if not keydata and keyfile:
            if not self.quiet: print "[*] keyfile: %s" % keyfile
            fd = open(keyfile, "rb")
            keydata = fd.read()
            fd.close()
        elif keydata:
            if not self.quiet: print "[*] keydata: %s" % keydata
        else:
            raise AssertionError, "keydata or keyfile required"

        encdata = self.encrypt(plaindata, keydata)
        if encfile:
            if not self.quiet: print "[*] creating encrypted file('%s')..." % encfile
            fd = open(encfile, "wb")
            fd.write(encdata)
            fd.close()
            if not self.quiet: print "[*] file saved!"

        if not self.quiet:
            print "[*] plain data size:", len(plaindata)
            print "[*] encrypted size:", len(encdata)
            print
        if not encfile:
            return encdata
        else:
            return


    def load_len_coeffs(self, encdata):
        # load length/coefficients from encdata
        c = 6 # encdata counter
        org_length,self.param_chars = unpack("<IH", encdata[:6])
        coefficients = []
        while c < len(encdata):
            coefficients.append([])
            dim = unpack("<H", encdata[c:c+2])[0] # dimension of the equation
            c += 2
            len_coeffs = []
            for i in xrange(dim*2):
                len_coeffs.append(unpack("<I", encdata[c:c+4])[0]) # length of the coefficient
                c += 4
            for l in len_coeffs:
                coefficients[-1].append(self.bin2int(encdata[c:c+l]))
                c += l
        self.num_of_params = dim - 4
        return org_length, coefficients

    def decrypt(self, encdata, key):
        # key: str
        # encdata : data to decrypt
        
        # load original length/coefficients from encdata
        org_length,coefficients = self.load_len_coeffs(encdata)
        # get key from sha512 hash of key
        keyhash = sha512(key).hexdigest()
        if not self.quiet: print "[*] keyhash:", keyhash
        while len(keyhash) < self.param_chars * self.num_of_keys * 2 * 2:
            keyhash += sha512(keyhash).hexdigest()
            if not self.quiet: print "[*] keyhash:", keyhash
        sol_keys = []
        for i in xrange(len(coefficients)):
            sol_keys.append([])
            for k in xrange(self.num_of_keys*2): # in each equation
                sol_keys[-1].append(int(keyhash[self.param_chars*2*k:self.param_chars*2*(k+1)], 16)*0x10 + (k % 8))
        # check plus or minus of keys
        for i in xrange(len(sol_keys)):
            for j in xrange(self.num_of_keys*2):
                if sol_keys[i][j] >> 39:
                    sol_keys[i][j] = -sol_keys[i][j]

        # lowering degree with key and solve quartic
        sol_params = []
        for coeffs,keys in zip(coefficients, sol_keys):
            sol_params.append([])
            output = self.run_maxima(self.SOLVE_QUARTIC() % tuple(coeffs + keys))
            output = output.split("(%o4)")[-1].strip()
            if "ERROR!" in output:
                raise KeyError, "incorrect key or broken encrypted data(%s)" % output
            sol_str_list = output[1:-1].split(",")
            for sol_str in sol_str_list:
                r = COMPLEX_RE.match(sol_str[4:].strip())
                if not r:
                    r = COMPLEX_RE2.match(sol_str[4:].strip())
                    if not r:
                        print "[!]", sol_str[4:].strip(), r
                        raise TypeError, "regular expression unmatch"
                sol_params[-1].append(int(r.group("realnum"))) # ignore sign
                sol_params[-1].append(int(r.group("imgnum")))
        # sort solution parameters
        for i,params in enumerate(sol_params):
            for j,p in enumerate(params):
                sol_params[i][j] = (p % 0x10, p / 0x10)
            sol_params[i].sort()
        # decode int to string
        decdata = ""
        for params in sol_params:
            for p in params:
                param_chr = ""
                num = p[1]
                while num > 255:
                    param_chr = chr(num % 256) + param_chr
                    num /= 256
                decdata += (chr(num) + param_chr)

        # cut junk data
        decdata = decdata[:org_length]
        return decdata
        
    def decrypt_with_file(self, encdata=None, encfile=None, keydata=None, keyfile=None, decfile=None):
        # encfile : str of file path to decrypt -> encdata
        # keyfile: str of file path to use as key to decrypt -> keydata
        # decfile: str of file path to save the decrypted data
        
        if not self.quiet:
            print
            print "< DECRYPT MODE >"

        if not encdata and encfile:
            if not self.quiet: print "[*] encfile: %s" % encfile
            fd = open(encfile, "rb")
            encdata = fd.read()
            fd.close()
        elif encdata:
            if not self.quiet: print "[*] encdata: %s" % encdata
        else:
            raise AssertionError, "encdata or encfile required"

        if not keydata and keyfile:
            if not self.quiet: print "[*] keyfile: %s" % keyfile
            fd = open(keyfile, "rb")
            keydata = fd.read()
            fd.close()
        elif keydata:
            if not self.quiet: print "[*] keydata: %s" % keydata
        else:
            raise AssertionError, "keydata or keyfile required"

        decdata = self.decrypt(encdata, keydata)
        if decfile:
            if not self.quiet: print "[*] creating decrypted file('%s')..." % decfile
            fd = open(decfile, "wb")
            fd.write(decdata)
            fd.close()
            if not self.quiet: print "[*] file saved!"
            
        if not self.quiet:
            print "[*] encrypted data size:", len(encdata)
            print "[*] decrypted size:", len(decdata)
            print
        if not decfile:
            return decdata
        else:
            return

    def crack(self, encdata_list, mode=SAME_KEY):
        # encdata_list: list of data to crack which have same key/plaindata
        # mode: crack mode (SAME_KEY or SAME_PLAIN)
        if not self.quiet:
            print
            print "< CRACK MODE >"
        sol_params = []
        org_len_list = []
        if mode == SAME_KEY:        
            # load length/coefficients from encdata (just like decrypt())
            for encdata in encdata_list:
                org_length, coefficients = self.load_len_coeffs(encdata)
                org_len_list.append(org_length)

                # factorize by force
                sol_params.append([])
                for coeffs in coefficients:
                    sol_params[-1].append([])
                    output = self.run_maxima(self.SOLVE_HIGH() % tuple(coeffs))
                    sol_str_list = output.split("(%o3)")[-1].strip()[1:-1].split(",")
                    for sol_str in sol_str_list:
                        r = COMPLEX_RE.match(sol_str[4:].strip())
                        if not r:
                            r = COMPLEX_RE2.match(sol_str[4:].strip())
                            if not r:
                                print "[!]", sol_str[4:].strip(), r
                                raise TypeError, "regular expression unmatch"
                        sol_params[-1][-1].append(
                            (int(r.group("realnum")), int(r.group("imgnum")) )
                            )
            #print "[*] sol_params:", [[[(hex(p[0]), hex(p[1])) for p in e] for e in d] for d in sol_params]
            key_params = []
            decdata_list = []
            # find common key for encdata_list[0]and[1]
            for e,base_sp in enumerate(sol_params[0]):
                key_params.append([])
                for p in base_sp:
                    if p in sol_params[1][e]:
                        key_params[-1].append(p)

            # check for encdata_list[2:]
            for params in sol_params[2:]:
                keys_check = key_params
                for e,e_params in enumerate(params):
                    for p in e_params:
                        if p in keys_check[e]:
                            keys_check[e].remove(p)
                if sum([len(l) for l in keys_check]) != 0:
                    raise TypeError, "the key may not be same for all encdata."
            if not self.quiet:
                print "[*] key_prams:", [[(hex(k[0]), hex(k[1])) for k in e_k]for e_k in key_params]
            # check if only key is matched and plaindata not matched
            for k_p in key_params:
                if len(k_p) != self.num_of_keys:
                    raise EnvironmentError, "accidentary plaindata matched. more encdata with same key needed."
            plain_params = []
            for s,sp in enumerate(sol_params):
                plain_params.append([])
                # sort and extract plain data
                for i,params in enumerate(sp):
                    plain_params[-1].append([])
                    for j,p in enumerate(params):
                        if not p in key_params[i]: # plain data
                            plain_params[-1][-1].append((p[0] % 0x10, p[0] / 0x10))
                            plain_params[-1][-1].append((p[1] % 0x10, p[1] / 0x10))
                    plain_params[s][i].sort()
                
                # decode int to string
                decdata = ""
                for params in plain_params[-1]:
                    for p in params:
                        param_chr = ""
                        num = p[1]
                        while num > 255:
                            param_chr = chr(num % 256) + param_chr
                            num /= 256
                        decdata += (chr(num) + param_chr)
    
                # cut JUNK data
                decdata = decdata[:org_len_list[s]]
                decdata_list.append(decdata)
            return decdata_list
        elif mode == SAME_PLAIN:
            # load length/coefficients from encdata (just like decrypt())
            for encdata in encdata_list:
                org_length, coefficients = self.load_len_coeffs(encdata)
                org_len_list.append(org_length)

                # factorize by force
                sol_params.append([])
                for coeffs in coefficients:
                    sol_params[-1].append([])
                    output = self.run_maxima(self.SOLVE_HIGH() % tuple(coeffs))
                    sol_str_list = output.split("(%o3)")[-1].strip()[1:-1].split(",")
                    for sol_str in sol_str_list:
                        r = COMPLEX_RE.match(sol_str[4:].strip())
                        if not r:
                            r = COMPLEX_RE2.match(sol_str[4:].strip())
                            if not r:
                                print "[!]", sol_str[4:].strip(), r
                                raise TypeError, "regular expression unmatch"
                        sol_params[-1][-1].append(int(r.group("realnum")))
                        sol_params[-1][-1].append(int(r.group("imgnum")))

            #print "[*] sol_params:", [[[(hex(p[0]), hex(p[1])) for p in e] for e in d] for d in sol_params]
            pass

                
        
    def int2bin(self, num):
        if self.debug:
            #print "[*] int2bin(" + str(num) + ")", "=", hex(num)
            pass
        if num < 0:
            data = "-"
            num = -num
        else:
            data = "+"
        while num > 255:
            data = chr(num % 256) + data
            num /= 256
        data = chr(num) + data
        return data

    def bin2int(self, bin):
        num = 0
        for i,c in enumerate(bin[-2::-1]):
            num += ord(c) * (256**i)
        if bin[-1] == "-":
            num = -num
        if self.debug:
            #print "[*] bin2int(bin) = ", hex(num)
            pass
        return num
        
    def run_maxima(self, batch):
        # batch : batch string for maxima
        if self.debug:
            print "[*] "+"="*19 +"maxima:"+"="*20
            print batch
        p = Popen(MAXIMA_EXEC+["--batch-string="+batch], stdout=PIPE)
        output = p.stdout.read()
        p.wait()
        if self.debug:
            print "[*] "+"="*19+"output:"+"="*20
            print output
            print "="*50, "\n"
        return output

    def benchmark(self):
        from itertools import product
        from benchmarker import Benchmarker
        ##from guppy import hpy
        self.quiet = True
        debug = self.debug
        self.debug = False
        
        bm = Benchmarker()
        for p, k in product(xrange(3, 21), xrange(1, 21)):
            self.param_chars = p
            self.num_of_keys = k
            with bm("encrypt/decrypt(p: %d, k: %d)" % (self.param_chars, self.num_of_keys)):
                encdata = self.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz This is plain data.", "This is key.")
                decdata = self.decrypt(encdata, "This is key.")
            assert decdata == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz This is plain data."

        #hp = hpy()
        #print hp.heap()

        self.debug = debug
        self.quiet = False
        return

    def crack_test(self):
        #from itertools import product
        #from benchmarker import Benchmarker
        
        #bm = Benchmarker()
        #for p,k in product(xrange(3,21), xrange(1, 21)):
        #self.quiet = True
        debug = self.debug
        self.debug = False
        
        encdata_list = [self.encrypt_with_file(plaindata="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789No.%d" % i, keydata="SAME KEY")
                        for i in range(1, 3)]
        for decdata in self.crack(encdata_list):
            print decdata
        return
        

if __name__ == "__main__":
    import sys
    q = HighPowered(debug=True)
    #q.benchmark()
    #encdata = q.encrypt_with_file(plaindata=sys.argv[1], keydata=sys.argv[2])
    #q.crack(encdata)
    
    #print q.decrypt_with_file(encfile="encdata.bin", keydata=sys.argv[2])
    q.crack_test()
