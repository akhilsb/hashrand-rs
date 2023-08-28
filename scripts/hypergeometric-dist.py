from scipy.stats import hypergeom
import math
import numpy as np

def estimate_samples(N, K, p):
    """
    Estimate the number of samples required from a hypergeometric distribution.

    Parameters:
    N (int): Total population size.
    K (int): Number of success states in the population.
    p (float): Desired probability threshold.

    Returns:
    int: Estimated number of samples required.
    """
    # n is the number of draws (i.e., quantity drawn in each trial)
    n = 1

    # Probability of getting at least one success
    prob = 1 - hypergeom.cdf(0, N, n, K)
    
    # Increment n until the probability of at least one success is greater than the threshold
    while prob < p:
        n += 1
        prob = 1 - hypergeom.cdf(0, N, n, K)
        #print(prob)
    return n

faults = np.arange(1,501,5)
samples_tril = []
samples_bil = []
for f in faults:
    samples_tril.append(estimate_samples(3*f+1,f+1,p=0.999999999999999))
    samples_bil.append(estimate_samples(3*f+1,f+1,p=0.999999999999))
print(samples_bil)
import matplotlib.pyplot as plt

plt.plot(3*faults+1,samples_tril,label=r'p = $1-10^{-15}$')
plt.plot(3*faults+1,samples_bil,label=r'p = $1-10^{-12}$')

plt.xlabel('Number of nodes')
plt.ylabel('Committee size')
plt.legend()
plt.savefig("committee_size_probability.jpg")
# Test the function
#N = 100  # total number of items
#K = 10   # total number of items of the desired kind

#print(estimate_samples(N, K))
