import numpy as np

def calculate_difference(n):
    """
    Draw n samples from a Gaussian distribution and calculate the difference between the maximum and minimum values.

    Args:
        n (int): Number of samples to draw from the Gaussian distribution.

    Returns:
        float: Difference between the maximum and minimum values of the n samples.
    """
    samples = np.random.normal(loc=52.5, scale=1.0,size=n)  # Draw n samples from Gaussian distribution
    difference = np.max(samples) - np.min(samples)  # Calculate the difference
    return difference

def calculate_average_difference(n, iterations):
    """
    Calculate the average of the differences between maximum and minimum values of n samples
    for a given number of iterations.

    Args:
        n (int): Number of samples to draw from the Gaussian distribution on each iteration.
        iterations (int): Number of iterations to perform.

    Returns:
        float: Average of the differences between maximum and minimum values.
    """
    differences = []  # List to store the differences between maximum and minimum values
    for i in range(iterations):
        difference = calculate_difference(n)
        differences.append(difference)
    average_difference = np.mean(differences)  # Calculate the average difference
    return average_difference

# Example usage
n = 16  # Number of samples to draw from Gaussian distribution on each turn
iterations = 1000000  # Number of iterations to perform
average_difference = calculate_average_difference(n, iterations)
print("Average difference between maximum and minimum values of", n, "samples after", iterations, "iterations:", average_difference)

