import numpy as np

# Define the size of the grid and the spacing between points
grid_size = 10
point_spacing = 1

# Define the location and signal strength of the target point
target_x = 4.5
target_y = 5.5
target_strength = 10

# Create a matrix to store the signal strengths at each point in the grid
signal_strengths = np.zeros((grid_size, grid_size))

# Generate the coordinates of the points in the grid
for i in range(grid_size):
    for j in range(grid_size):
        x = i * point_spacing
        y = j * point_spacing
        distance_squared = (x - target_x)**2 + (y - target_y)**2
        signal_strengths[i,j] = target_strength / distance_squared

# Print the signal strengths at each point in the grid
print(signal_strengths)
