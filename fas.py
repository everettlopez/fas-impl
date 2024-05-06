############################################################
#### Description:
# Our implementation of Functional Adaptor Signatures. 
############################################################

import random
import math

from utils import *
from schnorr import *
from adaptors import *
from ipfe import *
import settings 

# # Set DEBUG to True to get a detailed debug output including
# # intermediate values during key generation, signing, and
# # verification. This is implemented via calls to the
# # debug_print_vars(settings.DEBUG) function.
# #
# # If you want to print values on an individual basis, use
# # the pretty() function, e.g., print(pretty(foo)).
# DEBUG = True
# PS: DEBUG has been moved to settings.py

class advertisement:
	def __init__(self):
		self.mpk = None 
		self.ct0 = None 
		self.ct1 = None

class seller_state:
	def __init__(self):
		self.msk = None
		self.t = None 

def fas_adgen(faslen: int, bStatement: dict, witness: dict) -> (advertisement, seller_state):
	if len(bStatement) != faslen:
		raise ValueError('fas_adgen: The statement must be list of length: {}'.format(faslen))
	if len(witness) != faslen:
		raise ValueError('fas_adgen: The witness must be list of length: {}'.format(faslen))

	ipfelen = faslen + 1

	(mpk, msk) = ipfe_setup(ipfelen)

	t = {}
	for i in range(faslen):
		t_i = random.randint(0, n-1)
		t[i] = t_i

	witness_tilde = witness.copy() 
	witness_tilde[len(witness_tilde)] = 0
	(ct0, ct1) = ipfe_enc(ipfelen, mpk, witness_tilde)
	advt = advertisement()
	advt.mpk = mpk
	advt.ct0 = ct0
	advt.ct1 = ct1
	st = seller_state()
	st.msk = msk
	st.t = t

	debug_print_vars(settings.DEBUG)
	return (advt, st)

def fas_auxgen(faslen: int, advt: advertisement, st: seller_state, f: dict) -> (bytes, int):
	if len(f) != faslen:
		raise ValueError('fas_auxgen: The function must be list of length: {}'.format(faslen))
	if len(st.t) != faslen:
		raise ValueError('fas_auxgen: The st.t must be list of length: {}'.format(faslen))

	ipfelen = faslen + 1

	pi_f = compute_inner_product(f, st.t, n)
	f_tilde = f.copy()
	f_tilde[len(f_tilde)] = pi_f

	# optimized way to compute aux_f as seller knows st
	sk_f = ipfe_kgen(ipfelen, st.msk, f_tilde)
	aux_f = bytes_from_point(point_mul(G, sk_f))
	# aux_f_pub = ipfe_pubkgen(ipfelen, advt.mpk, f_tilde)


	debug_print_vars(settings.DEBUG)
	return (aux_f, pi_f)

def fas_auxverify(faslen: int, advt: advertisement, f: dict, aux_f: bytes, pi_f: int) -> bool:
	if len(f) != faslen:
		debug_print_vars(settings.DEBUG)
		raise ValueError('fas_auxverify: The function must be list of length: {}'.format(faslen))

	ipfelen = faslen + 1

	f_tilde = f.copy()
	f_tilde[len(f_tilde)] = pi_f
	if aux_f == ipfe_pubkgen(ipfelen, advt.mpk, f_tilde):
		return True 
	debug_print_vars(settings.DEBUG)
	return False

def fas_fpresign(faslen: int, advt: advertisement, seckey: bytes, msg: bytes, bStatement: dict, f: dict, aux_f: bytes) -> bytes:
	aux_rand = bytes_from_int(random.randint(1, n-1))
	debug_print_vars(settings.DEBUG)
	return as_presign(msg, seckey, aux_rand, aux_f)

def fas_fpreverify(faslen: int, advt: advertisement, pubkey: bytes, msg: bytes, bStatement: dict, f: dict, aux_f: bytes, pi_f: int, presig: bytes) -> bool:

	debug_print_vars(settings.DEBUG)
	return fas_auxverify(faslen, advt, f, aux_f, pi_f) and as_preverify(msg, pubkey, presig, aux_f)

def fas_adapt(faslen: int, advt: advertisement, st: seller_state, pubkey: bytes, msg: bytes, bStatement: dict, witness: dict, f: dict, aux_f: bytes, presig: bytes) -> bytes:
	if len(f) != faslen:
		raise ValueError('fas_auxgen: The function must be list of length: {}'.format(faslen))

	ipfelen = faslen + 1

	pi_f = compute_inner_product(f, st.t, n)
	f_tilde = f.copy()
	f_tilde[len(f_tilde)] = pi_f

	sk_f = ipfe_kgen(ipfelen, st.msk, f_tilde)

	sig = as_adapt(msg, pubkey, presig, aux_f, sk_f)

	debug_print_vars(settings.DEBUG)
	return sig

# def fas_fext(faslen: int, advt: advertisement, pubkey: bytes, presig: bytes, sig: bytes, bStatement: list[bytes], f: list[int], aux_f: bytes, pi_f: int, bound: int, msg_dict: dict) -> int:
def fas_fext(faslen: int, advt: advertisement, pubkey: bytes, presig: bytes, sig: bytes, bStatement: dict, f: dict, aux_f: bytes, pi_f: int, bound: int) -> int:

	ct2 = fas_fext_offline(faslen, advt, bStatement, f, pi_f)
	v = fas_fext_online(advt, pubkey, presig, sig, bStatement, aux_f, bound, ct2)

	debug_print_vars(settings.DEBUG)
	return v

def fas_fext_offline(faslen: int, advt: advertisement, bStatement: dict, f: dict, pi_f: int) -> bytes:

	ipfelen = faslen + 1

	f_tilde = f.copy()
	f_tilde[len(f_tilde)] = pi_f

	ct2 = ipfe_dec_offline(ipfelen, f_tilde, advt.ct1)

	debug_print_vars(settings.DEBUG)
	return ct2

def fas_fext_online(advt: advertisement, pubkey: bytes, presig: bytes, sig: bytes, bStatement: dict, aux_f: bytes, bound: int, ct2: bytes) -> int:

	sk_f = as_extract(msg, pubkey, presig, sig, aux_f)

	v = ipfe_dec_online(sk_f, advt.ct0, ct2, bound)

	debug_print_vars(settings.DEBUG)
	return v

if __name__ == '__main__':
	settings.init()

	len_range = (1, 100, 10000)
	# len_range = (20000, 30000, 40000, 50000)
	# len_range = (60000, 70000, 80000, 90000, 100000, 300000, 1000000, 30000000)
	# len_range = []
	# len_range.append(50000)
	# len_range.append(60000)
	# len_range.append(80000)
	# len_range.append(100000)

	# bound_range = (100, 10000)
	
	f_bound_range = (100, 1000)
	wit_bound_range = (100, 1000)
	# wit_bound_range = []
	# wit_bound_range.append(1000)
	# f_bound_range = []
	# f_bound_range.append(1000)

	# msg_dict = {}
	# dict_st = time.time()
	# with open('msg_dict.pkl', 'rb') as fp:
	# 	msg_dict = pickle.load(fp)
	# dict_et = time.time()
	# dict_time = dict_et - dict_st
	# print('DictTime: {}'.format(dict_time))

	print('faslen wit_bound f_bound TotalBound ExecTime AdGenTime AuxGenTime AuxVerifyTime FPreSignTime FPreVerifyTime AdaptTime VerifyTime FExtOffTime FExtOnTime')
	print('------ --------- ------- ---------- -------- --------- ---------- ------------- ------------ -------------- --------- ---------- ----------- ----------')

	for faslen in len_range:
		for wit_bound in wit_bound_range:
			for f_bound in f_bound_range:
				bound = faslen * wit_bound * f_bound # 100000
				msg = bytes_from_int(random.randint(1, n-1))
				witness = {}
				f = {}
				bStatement = {}
				actual_val = 0
				# print('check1')
				for i in range(faslen):
					witness_i = random.randint(1, wit_bound-1)
					witness[i] = witness_i
					f_i = random.randint(1, f_bound-1)
					f[i] = f_i
					# unused because NIZK not implemented
					bStatement[i] = bytes_from_int(0)
					actual_val = (actual_val + ((witness_i * f_i) %n)) % n

				seckey = bytes_from_int(3)
				pubkey = pubkey_gen(seckey)
				# print('check2')

				start_time = time.time()


				try:
					adgen_st = time.time()
					(advt, st) = fas_adgen(faslen, bStatement, witness)
					adgen_et = time.time()
					adgen_time = adgen_et - adgen_st
					# print('check3 adgen_time: {}'.format(adgen_time))

					try:
						auxgen_st = time.time()
						(aux_f, pi_f) = fas_auxgen(faslen, advt, st, f)
						auxgen_et = time.time()
						auxgen_time = auxgen_et - auxgen_st
						# print('check4 auxgen_time: {}'.format(auxgen_time))

						try:
							auxverify_st = time.time()
							aux_validity = fas_auxverify(faslen, advt, f, aux_f, pi_f)
							auxverify_et = time.time()
							auxverify_time = auxverify_et - auxverify_st
							# print('check5 auxverify_time: {}'.format(auxverify_time))

							if aux_validity:
								fpresign_st = time.time()
								presig = fas_fpresign(faslen, advt, seckey, msg, bStatement, f, aux_f)
								fpresign_et = time.time()
								fpresign_time = fpresign_et - fpresign_st
								# print('check6 fpresign_time: {}'.format(fpresign_time))

								fpreverify_st = time.time()
								presig_validity = fas_fpreverify(faslen, advt, pubkey, msg, bStatement, f, aux_f, pi_f, presig)
								fpreverify_et = time.time()
								fpreverify_time = fpreverify_et - fpreverify_st
								# print('check7 fpreverify_time: {}'.format(fpreverify_time))

								if presig_validity:

									try:
										adapt_st = time.time()
										sig = fas_adapt(faslen, advt, st, pubkey, msg, bStatement, witness, f, aux_f, presig)
										adapt_et = time.time()
										adapt_time = adapt_et - adapt_st
										# print('check8 adapt_time: {}'.format(adapt_time))

										try: 
											verify_st = time.time()
											sig_validity = schnorr_verify(msg, pubkey, sig)
											verify_et = time.time()
											verify_time = verify_et - verify_st
											# print('check9 verify_time: {}'.format(verify_time))

											if sig_validity:
												try:
													fext_off_st = time.time()
													ct2 = fas_fext_offline(faslen, advt, bStatement, f, pi_f)
													# extracted_val = fas_fext(faslen, advt, pubkey, presig, sig, bStatement, f, aux_f, pi_f, bound)
													fext_off_et = time.time()
													fext_off_time = fext_off_et - fext_off_st
													# print('check10 fext_off_time: {}'.format(fext_off_time))

													fext_on_st = time.time()
													extracted_val = fas_fext_online(advt, pubkey, presig, sig, bStatement, aux_f, bound, ct2)
													fext_on_et = time.time()
													fext_on_time = fext_on_et - fext_on_st
													# print('check10 fext_on_time: {}'.format(fext_on_time))

													if extracted_val != actual_val:
														print('fas: Extracted value INCORRECT. extracted_val: {}, actual_val: {}'.format(extracted_val, actual_val))
													# print('fas: Extracted value CORRECT. extracted_val: {}, actual_val: {}, witness: {}, f: {}'.format(extracted_val, actual_val, witness, f))

													end_time = time.time()
													elapsed_time = end_time - start_time 
													# print('faslen: {} \t wit_bound: {} \t f_bound: {} \t bound: {} \t ExecTime: {:.3f} \t AdGenTime: {:.3f} \t AuxGenTime: {:.3f} \t AuxVerifyTime: {:.3f} \t FPreSignTime: {:.3f} \t FPreVerifyTime: {:.3f} \t AdaptTime: {:.3f} \t VerifyTime: {:.3f} \t FExtOffTime: {:.3f} \t FExtOnTime: {:.3f}'.format(faslen, wit_bound, f_bound, bound, elapsed_time, adgen_time, auxgen_time, auxverify_time, fpresign_time, fpreverify_time, adapt_time, verify_time, fext_off_time, fext_on_time))
													print('{} \t\t {} \t {} \t 10^{} \t\t {:.3f} \t {:.3f} \t\t {:.3f} \t\t {:.3f} \t\t {:.3f} \t\t {:.3f} \t\t\t {:.3f} \t\t {:.3f} \t\t {:.3f} \t\t {:.3f}'.format(faslen, wit_bound, f_bound, int(math.log10(bound)), elapsed_time, adgen_time, auxgen_time, auxverify_time, fpresign_time, fpreverify_time, adapt_time, verify_time, fext_off_time, fext_on_time))
												except RuntimeError as e:
													print(' * fas_fext test raised exception:', e)

											if not sig_validity:
												print('fas: Adapted signature verification FAILED')
										except RuntimeError as e:
											print(' * schnorr_verify test raised exception:', e)

									except RuntimeError as e:
										print(' * fas_adapt test raised exception:', e)

								if not presig_validity:
									print('fas: FPreVerify FAILED')

							if not aux_validity:
								print('fas: AuxVerify FAILED')

						except RuntimeError as e:
							print(' * fas_auxverify test raised exception:', e)

					except RuntimeError as e:
						print(' * fas_auxgen test raised exception:', e)

				except RuntimeError as e:
					print(' * fas_adgen test raised exception:', e)




