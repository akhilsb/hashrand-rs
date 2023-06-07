import numpy as np
from scipy.stats import norm
from scipy.spatial import KDTree, Voronoi,voronoi_plot_2d
import matplotlib.pyplot as plt
from matplotlib.collections import PatchCollection
from matplotlib.patches import Polygon
import matplotlib.cm as cm

def compute_signal(n, a, tx, ty, S, mu, sigma):
    # Generate n*n grid of points
    grid = np.zeros((n, n))

    # Create a Gaussian random number generator
    rv = norm(loc=mu, scale=sigma)

    # List of all points and their signals
    points = []
    points_orig = []

    # Compute signal at each point in the grid
    for i in range(n):
        for j in range(n):
            # Compute Euclidean distance from target
            d = a * np.sqrt((tx - i)**2 + (ty - j)**2)
            # Get a random sample from the Gaussian distribution
            N = rv.rvs()
            # Avoid divide by zero
            # Avoid divide by zero
            if d < 1:
                S_0 = S
            else:
                # Compute the signal at the current point
                S_0 = np.log10(10**(S - 20*np.log10(d)) + 10**N)
            # Compute the signal at the current point
            # Store the signal in the grid
            grid[i, j] = S_0
            points.append(((i, j), S_0))
            points_orig.append(((i*a, j*a), S_0))

    return grid, points,points_orig

def compute_difference(n, k, grid, points):
    # Create k-d tree for efficient nearest neighbor search
    tree = KDTree([p[0] for p in points])

    # Compute absolute difference in signal strength
    for i in range(n):
        for j in range(n):
            # Find the first 2k+1 nearest points (considering 0-based indexing)
            dist, idx = tree.query((i, j), 2*k + 1)
            # Get the signal strengths of the first 2k+1 nearest points
            signals = [points[id][1] for id in idx[1:]]
            # Compute the difference between the maximum and minimum signal strengths
            max_diff = np.abs(max(signals) - min(signals))
            # Update the grid
            grid[i, j] = max_diff

    return grid

def plot_voronoi(n, grid, points,a):
    # Create Voronoi diagram
    import matplotlib,math
    # vor = Voronoi([p[0] for p in points])

    # # find min/max values for normalization
    # minima = 0.8
    # maxima = 13.5

    # # normalize chosen colormap
    # norm = matplotlib.colors.Normalize(vmin=minima, vmax=maxima, clip=True)
    # mapper = cm.ScalarMappable(norm=norm, cmap=cm.coolwarm)

    # # plot Voronoi diagram, and fill finite regions with color mapped from speed value
    # voronoi_plot_2d(vor, show_points=True, show_vertices=False, s=1)
    # for r in range(len(vor.point_region)):
    #     region = vor.regions[vor.point_region[r]]
    #     if not -1 in region:
    #         polygon = [vor.vertices[i] for i in region]
    #         plt.fill(*zip(*polygon), color=mapper.to_rgba(grid[int(polygon[0][0]), int(polygon[0][1])]))
    # sm = plt.cm.ScalarMappable(cmap=cm.coolwarm, 
    #     norm=plt.Normalize(vmin=0.8, vmax=13))
    # #ax.set_xlim([0, n-1])
    # #ax.set_ylim([0, n-1])
    # #fig.colorbar(sm, ax=ax)
    # plt.show()
    # Create Voronoi diagram
    #points_vor = []
    #for p in points:
    #    points_vor.append((p[0][0]*a,p[0][1]))
    #vor = Voronoi([p[0]*a for p in points])
    vor = Voronoi([p[0] for p in points])
    # Create Voronoi plot
    fig, ax = plt.subplots()
    
    # Create colormap for the Voronoi cells
    m = 0.38
    c = 1.10
    vmin = (m*math.log2(np.min(grid)*1000) + c)*19
    vmax = (m*math.log2(np.max(grid)*1000)+c)*19
    norm = matplotlib.colors.Normalize(vmin=vmin, vmax=vmax, clip=True)
    mapper = cm.ScalarMappable(norm=norm, cmap=cm.coolwarm)
    #cmap = plt.cm.get_cmap('coolwarm')
    #voronoi_plot_2d(vor, show_points=True, show_vertices=False, s=1)
    # Plot all grid points
    #voronoi_plot_2d(vor, show_points=True, show_vertices=False, s=1)
    # Plot Voronoi diagram with heatmap colors
    for region in vor.regions:
        if not -1 in region and len(region) > 0:
            polygon = [vor.vertices[i] for i in region]
            value = (m*math.log2(grid[int(polygon[0][0]/a), int(polygon[0][1]/a)]*1000)+c)*19
            ax.add_patch(Polygon(polygon, closed=True, fill=True, 
                color=mapper.to_rgba(value)))

    #ax.scatter([p[0][0] for p in points], [p[0][1] for p in points], c='black')
    
    # Set plot limits
    ax.set_xlim([0, int(n*a-a)])
    ax.set_ylim([0, int(n*a-a)])

    # Add colorbar
    cbar = fig.colorbar(mapper, ax=ax)
    cbar.set_label(r'Energy consumed (in J)',rotation=270, labelpad=10)
    # for i in range(n):
    #     for j in range(n):
    #         ax.scatter(i*a, j*a, c='black', s=10)
    #plt.show()
    plt.savefig("voronoi_diagram_heatmap_k=19_abr.pdf")

# Test the functions
n = 30
a = 4.4
S = 120
mu = 52.5
sigma = 1
k = 19
grid_m = np.zeros((n, n))
N = norm(loc=0, scale=0.5)
for i in range(100):
    tx, ty = 15+N.rvs(),15+N.rvs()
    grid, points,points_orig = compute_signal(n, a, tx, ty, S, mu, sigma)
    #print(grid)
    grid = compute_difference(n, k, grid, points)
    for i in range(n):
        for j in range(n):
            grid_m[i][j]+=grid[i][j]
    #print(grid)
plot_voronoi(n, grid_m/100, points_orig,a)