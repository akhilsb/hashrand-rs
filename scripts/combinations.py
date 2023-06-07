import itertools
import math
from tqdm import tqdm

# Get the number of H and T characters from the user
num_h = 50
num_t = 5

# Define the value of k
k_list = [9,10,11,12,13]

# Initialize a variable to keep track of the number of valid strings
count = [0,0,0,0,0]

# Generate all possible combinations of the positions of the H and T characters
positions = itertools.combinations(range(num_h + num_t), num_h)

# Initialize a progress bar with the total number of combinations
progress_bar = tqdm(total=math.comb(num_h + num_t, num_h))

# For each combination of positions, generate the corresponding string
for pos in positions:
    # Create a list of 50 characters, initialized to 'T'
    string_list = ['T'] * (num_h + num_t)
    # Set the characters at the selected positions to 'H'
    for i in pos:
        string_list[i] = 'H'
    # Check if the string satisfies the condition
    index = 0
    for k in k_list:
        valid = True
        for i in range(len(string_list) - k + 1):
            group = string_list[i:i+k]
            if group.count('T') > k // 3:
                valid = False
                break
        # If the string satisfies the condition, print it and increment the count
        if valid:
            #print(''.join(string_list))
            count[index] += 1
        index +=1
    # Update the progress bar
    progress_bar.update(1)

# Finish the progress bar
progress_bar.close()

# Print the number of valid strings and the ratio of valid strings to total possible strings
total_strings = math.comb(num_h + num_t, num_h)
print(f"Total valid strings: {count}/{total_strings} ({count/total_strings:.6f})")
