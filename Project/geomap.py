import geopandas as gpd
from shapely.geometry import Point
import matplotlib.pyplot as plt
import pandas as pd

# Read the CSV file
file_path = 'All-Messages-search-result(3).csv'
df = pd.read_csv(file_path)

# Filter out rows with missing or incorrect coordinates
df = df.dropna(subset=['dst_ip_geolocation'])
df = df[df['dst_ip_geolocation'].apply(lambda x: len(str(x).split(',')) == 2 if isinstance(x, str) else False)]

# Create a GeoDataFrame with the filtered coordinates
geometry = [Point(xy.split(',')) for xy in df['dst_ip_geolocation']]
gdf = gpd.GeoDataFrame(df, geometry=geometry, crs="EPSG:4326")

# Plot the world map
world = gpd.read_file(gpd.datasets.get_path('naturalearth_lowres'))
fig, ax = plt.subplots(figsize=(15, 10))
world.plot(ax=ax, color='lightgrey')

# Plot the GeoDataFrame on top of the world map
gdf.plot(ax=ax, marker='o', color='red', markersize=50, alpha=0.7)

# Add labels for each point (optional)
for x, y, label in zip(gdf.geometry.x, gdf.geometry.y, gdf['dst_ip_geo_city_name']):
    ax.text(x, y, label, fontsize=8, ha='right')

plt.title('Locations on World Map')
plt.show()
