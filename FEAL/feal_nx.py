from FEAL.utils import *

class Feal_NX():
	def __init__(self,rounds,key):
		assert rounds > 0, 'Number of Round must be > 0'
		assert len(key) == 16, 'Key must be 16 characters.'

		self.N = rounds
		self.key = key
		self.subkey = self.key_generation(key,rounds)

	def key_generation(self,key,rounds):
		subkeys = [0] * (rounds//2+4)
		"""
		Qr = KR1 ⊕ KR2 for r = 1, 4, 7..., (r = 3i+1; i = 0, 1, ...)
		Qr = KR1 for r = 2, 5, 8..., (r = 3i+2; i = 0, 1, ...)
		Qr = KR2 for r = 3, 6, 9..., (r = 3i+3; i = 0, 1, ...)
		where 1 ≦ r ≦ (N/2)+4, (N ≧ 32, N: even)
		"""
		Kl,Kr   = key[:8],key[8:]	
		Kr1,Kr2 = Kr[:4],Kr[4:]
		Qr 		= xor(Kr1,Kr2)
		'''
		Let A0 be the left half of KL and let B0 be the right half, i.e., (A0, B0)=KL. Set
		D0 = φ, 
		& (4) φ : zero block, 32-bits long
		'''
		A0,B0 	= Kl[:4],Kl[4:]
		D0 = [0]*4

		'''then calculate Ki (i=0 to N+7) for r =1 to (N/2)+4. '''
		for i in range(rounds//2+4):
			if(i % 3 == 1):		xored = xor(B0,Kr1)
			elif(i % 3 == 0):	xored = xor(B0,Qr)
			else:				xored = xor(B0,Kr2)
			xored = xor(xored, D0) if i > 0 else xored
			D0 = A0[0:4]
			'''
			Br = fK(α, β) = fK (Ar-1, (Br-1 ⊕ Dr-1) ⊕ Qr)) 
			'''
			b = A0
			A0 = Fk(A0, xored)
			'''
			K2(r-1) = (Br0, Br1)
			K2(r-1)+1 = (Br2, Br3) 
			'''
			subkeys[4 * i: 4 * i + 2] = A0[0:2]
			subkeys[4 * i + 2: 4 * i + 4] = A0[2:4]
			A0, B0 = B0, A0

		return subkeys

	def encrypt(self,data):
		pad   = lambda data : data + bytes([0x00 for _ in range((8-len(data))%8)])
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		data = pad(data)
		φ = [0]*4

		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]
			'''P is separated into L0 and R0 both 32-bits long'''
			L,R = split(bloc)
			'''(L0, R0) = (L0, R0) ⊕ (K32, K33, K34, K35 ) '''
			L,R = split(xor(L+R,self.subkey[2*self.N:2*self.N+8]))
			'''(L0, R0) = (L0, R0) ⊕ ( φ , L0) '''
			L,R = split(xor(L+R,φ+L))

			for i in range(self.N):
				L = xor(L,F2(R,self.subkey[2*i:2*(i+1)]))
				L,R = R,L
			
			'''(R32, L32 ) = (R32, L32 ) ⊕ ( φ , R32) '''
			R,L = split(xor(R+L,[0]*4+R))

			'''(R32, L32 ) = (R32, L32 ) ⊕ (K36, K37, K38, K39 ) '''
			R,L = split(xor(R+L,self.subkey[2*self.N+8:2*(self.N+8)]))

			'''Ciphertext is given as (R32, L32 )'''
			result += R+L

		return bytes(result)
					

	def decrypt(self,data):
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		φ = [0]*4

		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]

			'''Ciphertext (RN, LN) is separated into RN and LN of equal lengths'''
			R,L = split(bloc)
			
			'''(RN , LN)= (RN, LN) ⊕ (KN+4, KN+5, KN+6, KN+7)'''
			R,L = split(xor(R+L,self.subkey[2*self.N+8:2*(self.N+8)]))

			'''(RN , LN)= (RN, LN) ⊕ ( φ , RN)'''
			R,L = split(xor(R+L,φ+R))

			for i in reversed(range(self.N)):
				'''Lr-1 = Rr ⊕ f (Lr, Kr-1) & Rr-1 = Lr'''
				L,R = R,L
				L = xor(L,F2(R,self.subkey[2*i:2*(i+1)]))

			'''(L0 , R0)= (L0, R0) ⊕ ( φ , L0) '''
			L,R = split(xor(L+R,φ+L))

			'''(L0, R0)= (L0, R0) ⊕ (KN, KN+1, KN+2, KN+3) '''
			L,R = split(xor(L+R,self.subkey[2*self.N:2*self.N+8]))

			result += L+R

		return bytes(result)