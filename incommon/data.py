COMODO_SERVER_TYPES = {
    'AOL':1,
    'Apache/ModSSL':2,
    'Apache-ModSSL':2,
    'Apache-SSL (Ben-SSL, not Stronghold)':3,
    'C2Net Stronghold':3,
    'Cisco 3000 Series VPN Concentrator':33,
    'Citrix':34,
    'Cobalt Raq':5,
    'Covalent Server Software':6,
    'IBM HTTP Server':7,
    'IBM Internet Connection Server':8,
    'iPlanet':9,
    'Java Web Server (Javasoft / Sun)':10,
    'Lotus Domino':11,
    'Lotus Domino Go!':12,
    'Microsoft IIS 1.x to 4.x':13,
    'Microsoft IIS 5.x and later':14,
    'Netscape Enterprise Server':15,
    'Netscape FastTrac':16,
    'Novell Web Server':17,
    'Oracle':18,
    'Quid Pro Quo':19,
    'R3 SSL Server':20,
    'Raven SSL':21,
    'RedHat Linux':22,
    'SAP Web Application Server':23,
    'Tomcat':24,
    'Website Professional':25,
    'WebStar 4.x and later':26,
    'WebTen (from Tenon)':27,
    'Zeus Web Server':28,
    'Ensim':29,
    'Plesk':30,
    'WHM/cPanel':31,
    'H-Sphere':32,
    'OTHER':-1,
}

COMODO_SERVER_TYPE_NAMES = list(sorted(COMODO_SERVER_TYPES.keys()))

# Notice the extra spaces...stay classy Comodo
AVAILABLE_CERTIFICATE_TYPES = [
   "InCommon SSL",
   "InCommon Intranet SSL",
   "InCommon Wildcard SSL Certificate ",
   "InCommon Multi Domain SSL ",
   "InCommon Unified Communications Certificate",
   "Comodo EV SGC SSL ",
   "Comodo EV Multi Domain SSL",
]

WEB_SSL_CERT = "InCommon SSL"
