import pandas as pd
import matplotlib.pyplot as plt

# Read CSV file into a DataFrame
df = pd.read_csv('All-Messages-search-result(3).csv', parse_dates=['timestamp'])

# Extract relevant columns
df_logs = df[df['message'].str.startswith('Mock log message with IP')]

# Plotting the geolocations on a world map
fig, ax = plt.subplots(figsize=(10, 6))
scatter = ax.scatter(df_logs['dst_ip_geolocation'].str.split(',', expand=True).astype(float)[1],
                     df_logs['dst_ip_geolocation'].str.split(',', expand=True).astype(float)[0],
                     c=df_logs.index, cmap='viridis', s=100, alpha=0.7)

# Add labels and title
ax.set_xlabel('Longitude')
ax.set_ylabel('Latitude')
ax.set_title('Geolocations of Mock Log Messages')

# Add a colorbar
cbar = plt.colorbar(scatter)
cbar.set_label('Log Entry Index')

# Show the plot
plt.show()
