import geoip2.database

reader = geoip2.database.Reader('./GeoLite2-City.mmdb')

ipReceived = input("Insert IP: ")

returndata = reader.city(ipReceived)

print ("Country: " + returndata.country.iso_code)
print (returndata.city.name)
print (returndata.subdivisions.most_specific.name)

