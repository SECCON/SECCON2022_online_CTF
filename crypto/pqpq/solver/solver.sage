with open("output.txt") as f:
    for line in f:
        exec(line)

q = int(gcd(c1-c2,n))
c1q = int(pow(q,e,n))
p = int(gcd(c1+c1q, n))
r = int(n // p // q)

assert p*q*r == n

_,d,_ = xgcd(e,(p-1)*(q-1)*(r-1))
# a == e*b + phi*c

cm2 = pow(cm,d,n)

cm2p = cm2 % p
mp = int(cm2p.sqrt())
mps = [mp, p-mp]
cm2q = cm2 % q
mq = int(cm2q.sqrt())
mqs = [mq, q-mq]
cm2r = cm2 % r
mr = int(cm2r.sqrt())
mrs = [mr, r-mr]

res = ""

for i in range(2):
    for j in range(2):
        for k in range(2):
            temp = int(crt([mps[i],mqs[j],mrs[k]],[p,q,r])).to_bytes(256, byteorder='big')
            if b"SECCON{" in temp:
                print(temp[temp.find(b"SECCON{"):].decode('utf-8'))
