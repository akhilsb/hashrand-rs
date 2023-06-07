import itertools
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import numpy as np

def check_T_fraction(s, k):
    for i in range(len(s) - k + 1):
        #print(f"k:{k}, k/3:{int(k/3)}")
        if s[i:i+k].count('T') > k//3:
            return False
    return True

def check_T_fraction_sharding(s, k):
    import math
    shards = math.ceil(len(s)/k)
    for i in range(shards):
        #print(f"k:{k}, k/3:{int(k/3)}")
        start = i*k
        end = i*(k)+k
        if end >= len(s):
            end = len(s)-1
        if s[start:end].count('T') > k//3:
            return False
    return True

def build_string_and_check(args):
    combination, k_s,k_e, n = args
    s = ['H'] * n
    for index in combination:
        s[index] = 'T'
    k_arr = np.arange(3*k_s+1,3*k_e+1,3)
    k_out = []
    for k in k_arr:
        k_out.append(check_T_fraction_sharding(s, k))
    return k_out

def calc_permutations(n, h, k_s,k_e, p):
    t = n - h

    # Generate all combinations of indices
    total_combinations = list(itertools.combinations(range(n), t))

    #for k in ks:
        # Build string and check each combination in parallel
    with Pool(cpu_count()) as pool:
        args = [(c, k_s,k_e, n) for c in total_combinations]
        #print(args)
        vals = [0]*(k_e-k_s)
        for x in tqdm(pool.imap(build_string_and_check, args), total=len(total_combinations)):
            for i in range(len(x)):
                vals[i] += x[i]
        #valid_permutations = sum()
    # Calculate ratio
    print(np.array(vals)/len(total_combinations))
    #ratio = valid_permutations / len(total_combinations)

    # Check if ratio is below the threshold
    #print(f"Ratio : {ratio}, k:{k}")

    return None, None

# Test
n, h, k_s,k_e, p = 50, 46, 1,5, 0.99
k, ratio = calc_permutations(n, h, k_s,k_e, p)
if k is not None:
    print(f"The ratio of valid permutations falls below {p} when k = {k}, with a ratio of {ratio}.")
else:
    print(f"The ratio of valid permutations never falls below {p} for these k values.")
