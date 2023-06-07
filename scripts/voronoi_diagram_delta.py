import numpy as np
from scipy.stats import norm

def compute_signal(n, a, tx, ty, S, mu, sigma):
    # Generate n*n grid of points
    grid = np.zeros((n, n))

    # Create a Gaussian random number generator
    rv = norm(loc=mu, scale=sigma)

    # Compute signal at each point in the grid
    for i in range(n):
        for j in range(n):
            # Compute Euclidean distance from target
            d = np.sqrt((tx - a*i)**2 + (ty - a*j)**2)
            # Get a random sample from the Gaussian distribution
            N = rv.rvs()
            # Avoid divide by zero
            if d < 1:
                S_0 = S
            else:
                # Compute the signal at the current point
                S_0 = np.log10(10**(S - 20*np.log10(d)) + 10**N)
            # Store the signal in the grid
            grid[i, j] = S_0

    return grid

# Test the function
n = 10
a = 5.0
tx, ty = 25, 25
S = 75
mu = 52.5
sigma = 1
grid = compute_signal(n, a, tx, ty, S, mu, sigma)
print(grid)