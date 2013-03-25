#!/usr/bin/env python
#-*- coding:utf-8 -*-

from subprocess import Popen, PIPE
from hashlib import sha512
from random import sample, randint
import re

# each solution parameter contains plain data(PARAM_CHARS byte) and order number(8bit)
# so, if PARAM_CHARS=5, it can be 0xFFFFFFFFFFF = 17592186044415 at most
PARAM_CHARS = 5
JUNK = "\xff" # for padding
NUM_OF_KEYS = 2 # encrypted equation will be (4+NUM_OF_KEYS)-dimensional

MAXIMA_EXEC = ["/Applications/Maxima.app/Contents/Resources/maxima/bin/sbcl", # on my mac os
               "--core",
               "/Applications/Maxima.app/Contents/Resources/maxima/lib/maxima/5.28.0/binary-sbcl/maxima.core",
               "--noinform", "--end-runtime-options", "--eval", "(cl-user::run)", "--end-toplevel-options",
               "-q", "--disable-readline",] # "--batch-string="

# Maxima batch string
EXPAND_POLY = "display2d:false$linel:10000$" +\
              "poly:expand((x-(%+d%+d*%%i))*(x-(%+d%+d*%%i))*(x-(%+d%+d*%%i))*(x-(%+d%+d*%%i))" + "*(x-(%+d%+d*%%i))"*NUM_OF_KEYS + ")$\n" +\
              "[" + ",".join(["ratsimp(coeff(poly, x, %d))"%i for i in xrange(4+NUM_OF_KEYS-1, -1, -1)]) + "];" # to encrypt
SOLVE_QUARTIC = "display2d:false$linel:10000$" +\
                "quartic:divide(x^%d" % (4+NUM_OF_KEYS) + "".join(["%+d*x^"+"%d"%i for i in xrange(4+NUM_OF_KEYS-1, -1, -1)]) + ", " "*".join(["(x%+d)" for i in xrange(NUM_OF_KEYS)]) + ")$\n" +\
                "if quartic[2]#0 then print(\"ERROR!\"), quit();\n" +\
                "solve(gfactor(quartic[1]));"
# to decrypt with key
### key must flip sign

# regular expressions for Maxima output 
COMPLEX_RE = re.compile(r"(?P<sign1>[-]?)(?P<imgnum>\d+)[*]%i(?P<sign2>[+\-])(?P<realnum>\d+)")
COMPLEX_RE2 = re.compile(r"(?P<sign1>[-]?)(?P<realnum>\d+)(?P<sign2>[+\-])(?P<imgnum>\d+)[*]%i")


class HighPowered(object):
    def __init__(self, plaindata, debug=False):
        # plaindata : str
        self.debug = debug
        self.plaindata = plaindata + JUNK * (PARAM_CHARS*8 - len(plaindata) % (PARAM_CHARS*8))

    def encrypt(self, key, encfile="encdata.bin"):
        # key : str
        # encfile : str of file path to save the encrypted data

        # create equations regarding data/key as solution parameters
        sol_params = []
        # data to params
        for i,c in enumerate(self.plaindata):
            if i % (8*PARAM_CHARS) == 0: # new equation
                sol_params.append([j for j in xrange(8)])
            sol_params[-1][(i%(PARAM_CHARS*8))/PARAM_CHARS] += ord(c)*0x100 ** (PARAM_CHARS - (i % PARAM_CHARS) - 1) * 0x10
        if self.debug:
            print "[*] sol_params(hex): [" + ", ".join(["["+", ".join([hex(c) for c in param])+"]" for param in sol_params]) + "]"
            #print "[*] sol_params(deci):", sol_params

        # shuffle params list => 8!(=479001600) patterns
        sol_params = [sample(param, 8) for param in sol_params]
        # key to params
        keyhash = sha512(key).hexdigest()
        if self.debug: print "[*] keyhash:", keyhash
        while len(keyhash) < NUM_OF_KEYS * 10:
            keyhash += sha512(keyhash).hexdigest()
            if self.debug: print "[*] keyhash:", keyhash
        for i in xrange(len(sol_params)):
            for k in xrange(NUM_OF_KEYS*2):
                sol_params[i].append(int(keyhash[10*k:10+10*k], 16)*0x10 + randint(0, 8))
        
        # check plus or minus
        for i in xrange(len(sol_params)):
            for j in xrange(8+NUM_OF_KEYS*2):
                if sol_params[i][j] >> 39:
                    sol_params[i][j] = -sol_params[i][j]
        if self.debug:
            print "[*] sol_params(hex): [" + ", ".join(["["+", ".join([hex(c) for c in param])+"]" for param in sol_params]) + "]"
            #print "[*] sol_params(deci):", sol_params
        
        # calc coefficients of the equations
        coefficients = []
        for param in sol_params:
            coefficients.append([])
            output = self.run_maxima(EXPAND_POLY % tuple(param))
            #print output
            coeff_str_list = output.split("(%o4)")[-1].strip()[1:-1].split(",")
            for coeff_str in coeff_str_list:
                r = COMPLEX_RE.match(coeff_str.strip())
                if not r:
                    r = COMPLEX_RE2.match(coeff_str.strip())
                    if not r:
                        print "[!]", coeff_str.strip(), r
                        raise TypeError
                coefficients[-1].append((int(r.group("sign1")+r.group("imgnum")), int(r.group("sign2")+r.group("realnum"))))

        print "[*] creating encrypted file..."
        fd = open(encfile, "wb")
        for coeffs in coefficients:
            equ_header = self.int2bin(len(coeffs))+"\x00"
            equ_body = ""
            cur = 0
            for coeff in coeffs:
                equ_body += self.int2bin(coeff[0])
                equ_header += self.int2bin(len(equ_body) - cur) + "\x00"
                cur = len(equ_body)
                equ_body += self.int2bin(coeff[1])
                equ_header += self.int2bin(len(equ_body) - cur) + "\x00"
                cur = len(equ_body)
            fd.write(equ_header + equ_body)
        print "[*] plain data size:", len(self.plaindata)
        print "[*] encrypted size:", fd.tell()
        fd.close()
        print "[*] file saved!"
        print 
        print 
        return

    def int2bin(self, num):
        if self.debug:
            #print "[*] int2bin(" + str(num) + ")", "=", hex(num)
            pass
        if num < 0:
            data = "-"
            num = -num
        else:
            data = ""
        while num > 255:
            data = chr(num % 256) + data
            num /= 256
        data = chr(num) + data
        return data
        
    def run_maxima(self, batch):
        # batch : batch string for maxima
        if self.debug:
            print "[*] "+"="*19 +"maxima:"+"="*20
            print batch
            print "="*50
        p = Popen(MAXIMA_EXEC+["--batch-string="+batch], stdout=PIPE)
        output = p.stdout.read()
        p.wait()
        if self.debug:
            print "[*] "+"="*19+"output:"+"="*20
            print output
            print "="*50, "\n"
        return output

if __name__ == "__main__":
    import sys
    q = HighPowered(sys.argv[1], debug=True)
    q.encrypt(sys.argv[2])
