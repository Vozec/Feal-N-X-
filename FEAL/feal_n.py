from FEAL.utils import *

class Feal_N():
	def __init__(self,rounds,key):
		assert rounds > 4, 'Number of Round must be > 4'
		assert len(key) == 8, 'Key must be 8 characters.'

		self.N = rounds
		self.key = key
		self.subkey = self.key_generation(key,rounds)
		

	def key_generation(self,key,rounds):
		# https://link.springer.com/content/pdf/10.1007/3-540-38424-3_46.pdf
		subkeys = [0] * (rounds//2+4)

		Kl,Kr   = key[:8],[0]*8
		Kr1,Kr2 = Kr[:4],Kr[4:]
		Qr 		= xor(Kr1,Kr2)
	
		A0,B0 	= Kl[:4],Kl[4:]
		D0 = [0]*4

		for i in range(rounds//2+4):
			if(i % 3 == 1):		xored = xor(B0,Kr1)
			elif(i % 3 == 0):	xored = xor(B0,Qr)
			else:				xored = xor(B0,Kr2)
			xored = xor(xored, D0) if i > 0 else xored
			D0 = A0[0:4]
		
			b = A0
			A0 = Fk(A0, xored)
		
			subkeys[4 * i: 4 * i + 2] = A0[0:2]
			subkeys[4 * i + 2: 4 * i + 4] = A0[2:4]
			A0, B0 = B0, A0

		return subkeys

	# https://doc.lagout.org/security/Crypto/XXXX_FEAL.pdf
	def encrypt(self,data):
		pad   = lambda data : data + bytes([0x00 for _ in range((8-len(data))%8)])
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		data = pad(data)

		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]
			L,R = split(bloc)

			L,R = split(xor(L+R,self.subkey[-2*8:-8]))
			R = xor(L,R)

			for i in range(self.N):
				# L = xor(L,F1(xor(R,self.subkey[i*4:(i+1)*4])))
				L = xor(L,F2(R,self.subkey[i*2:(i+1)*2]))
				L,R = R,L
			
			L,R = R,L
			R = xor(R,L)

			if self.N > 4:
				L,R = split(xor(L+R,self.subkey[-8:]))
			result += L+R

		return bytes(result)
					
	def decrypt(self,data):
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]
			L,R = split(bloc)

			if self.N > 4:
				L,R = split(xor(L+R,self.subkey[-8:]))

			R = xor(L,R)
			L,R = R,L
			for i in reversed(range(self.N)):
				L,R = R,L
				L = xor(L,F2(R,self.subkey[i*2:(i+1)*2]))
			
			R = xor(R,L)
			L,R = split(xor(L+R,self.subkey[-2*8:-8]))
			result += L+R
		return bytes(result)

