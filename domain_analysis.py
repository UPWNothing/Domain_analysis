#! /usr/bin/python
# encoding utf8

import sys
import argparse
import subprocess
import os
import hashlib
import json

try:
    from whois import whois
    from urlparse import urlparse
    from tld import get_tld
    from requests import get
    from sqlalchemy import Column, Integer, Float, String, Text
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import create_engine
    import simplekml
except ImportError as e:
    module_name = e.message[16:]
    print e
    print "Module \'{0}\' not installed".format(module_name)
    if module_name in ['whois','tld','requests','simplekml']:
        print "Try:[sudo] pip install {}".format(module_name)
    sys.exit()


Base = declarative_base()

# ====================   WhoisInfo Class   =========================
class WhoisInfo(Base):
    
    __tablename__ = 'whoisInfo'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String)
    updated_date = Column(String)
    status = Column(String)
    name = Column(String)
    dnssec = Column(String)
    city = Column(String)
    expiration_date = Column(String)
    address = Column(String)
    zipcode = Column(String)
    domain_name  = Column(String)
    whois_server = Column(String)
    state = Column(String)
    registrar = Column(String)
    referral_url = Column(String)
    country = Column(String)
    name_servers = Column(String)
    org = Column(String)
    creation_date = Column(String)
    emails = Column(String)

    def __init__(self,ip_address,json):
        self.ip_address = ip_address
        self.updated_date = str(json['updated_date'])
        self.status = str(json['status'])
        self.name = str(json['name'])
        self.dnssec = str(json['dnssec'])
        self.city = str(json['city'])
        self.expiration_date = str(json['expiration_date'])
        self.address = str(json['address'])
        self.zipcode = str(json['zipcode'])
        self.domain_name = str(json['domain_name'])
        self.whois_server = str(json['whois_server'])
        self.state = str(json['state'])
        self.registrar = str(json['registrar'])
        self.country = str(json['country'])
        self.name_servers = str(json['name_servers'])
        self.org = str(json['org'])
        self.creation_date = str(json['creation_date'])
        self.emails = str(json['emails'])

# ====================  End DomainInfo Class  =======================


# ====================  OSDetection Class   =========================
class OSDetection(Base):
    __tablename__ = 'osDetection'

    id = Column(Integer,primary_key=True)
    ip_address = Column(String)
    device_type = Column(String)
    running = Column(String)
    os_cpe = Column(String)

    def __init__(self,ip_address,json):
        self.ip_address = ip_address
        self.device_type= json['Device type']
        self.running = json['Running']
        self.os_cpe = json['OS CPE']
# ===================  End OSDetection Class   ======================


# =====================  GeoLocation Class   ========================
class GeoLocation(Base):
    __tablename__ = 'geoLocation'

    id = Column(Integer,primary_key=True)
    ip_address = Column(String)
    longitude = Column(Float)
    latitude = Column(Float)
    city = Column(String)
    region_code = Column(String)
    region_name = Column(String)
    time_zone = Column(String)
    metro_code  = Column(String)
    country_code = Column(String)
    country_name = Column(String)
    zip_code = Column(Integer)

    def __init__(self,json):
        self.ip_address = json['ip']
        self.longitude = json['longitude']
        self.latitude = json['latitude']
        self.city = json['city']
        self.region_code = json['region_code']
        self.region_name = json['region_name']
        self.time_zone = json['time_zone']
        self.metro_code = json['metro_code']
        self.country_code = json['country_code']
        self.country_name = json['country_name']
        self.zip_code = json['zip_code']

# ====================  End GeoLocation Class  ======================


# ====================   DomainAnalysis Class   =====================
class DomainAnalysis(object):
    def __init__(self, session, kml, url):
        """
        Initialize DomainAnalysis Class

        @type   session: Session()  
        @param  session: handle the connection with SQLite Database. 
                         session value is '' when database output is disabled

        @type   kml: Kml()
        @param  kml: simplekml object. 
                     kml value is '' when kml output is disabled

        @type   url: string
        @param  url: target url
        """
        if url is '':
            raise Exception('Empty URL')
        try:
            # Get Domain Name From URL
            # ref: http://stackoverflow.com/questions/9626535/get-domain-name-from-url
            parsed_uri = urlparse(url)
            self.url = url
            self.hostname = '{uri.netloc}'.format(uri=parsed_uri)
            self.domain = get_tld(url) 
        except:
            raise Exception('Invalid URL: {}'.format(self.url))
        self.session = session
        self.kml = kml

    def get_whois(self):
        '''
        Get whois info and return data in json
        '''
        self.whois_json = json.loads(str(whois(self.domain)))
        return self.whois_json

    def get_ip(self):
        '''
        Get IP address of target url.
        Use command: host -t a [hostname]

        IP address is stored in self.ip
        host command result is stored in self.ip_info
        '''
        try:
            self.ip_info = subprocess.check_output(['host','-t','a',self.hostname])
            self.ip = self.ip_info[self.ip_info.find("address",10)+8:self.ip_info.find('\n',self.ip_info.find("address",10))]
        except Exception as e:
            print "[*] Failed to get IP address of `{}`.".format(self.url)
            self.ip_info = None

    def fingerprint_os(self):
        '''
        Get OS information on traget url
        use command: nmap -T4 -Pn -n -O -top--ports 10 [hostname]

        Data is stored as JSON in self.os_json 
        '''
        try:
            nmap_para = ['nmap','-T4','-Pn','-n','-O','-top-ports','10',self.hostname]
            nmap_result = subprocess.check_output(nmap_para)
        except Exception as e:
            print "[*] Root privilege is required to perform os detection."
            sys.exit()
        # Seperate detected OS information from nmap output
        os_info = nmap_result[nmap_result.find('Device type:'):nmap_result.find('OS detection performed')]
        os_info_arr = os_info.split('\n')
        self.os_json = {}
        for ent in os_info_arr:
            if not ent:
                continue
            ent_arr = ent.split(': ',1)
            self.os_json[ent_arr[0]] = ent_arr[1]
        try:
            self.os_json = json.loads(json.dumps(self.os_json))
        except Exception as e:
            print "[*] Failed to perform OS detection on {}({})".format(self.url,self.ip)
            self.os_json = None

    def get_geo(self):
        '''
        retrive host's geolocation using http://freegeoip.net API    
        Use after get_ip()

        result is stored as JSON in self.geo_json

        '''
        # IP Address validation
        if not self.ip:
            raise Exception("Invalid IP") 
        # send request
        try:
            url = 'http://freegeoip.net/json/{}'.format(self.ip)
            res = get(url)
            self.geo_json = res.json()
        except:
            print "[*] Failed to get Geolocation of {}({})".format(self.url,self.ip)

    def write_report(self,target):
        """
        Write report to target path
        
        @type   target: string
        @param  target: target path

        """
        with open(target,'a') as f:
            name = '  {}({})  '.format(self.url,self.ip)
            f.write('+'+'-'*len(name)+'+\n|{}|\n+'.format(name)+'-'*len(name)+'+\n\n')
            # Write Whois Info
            if self.whois_json:
                f.write('Whois Information:\n'+'-'*80+'\n')    
                for key,value in self.whois_json.iteritems():
                    if not isinstance(value,list):
                        f.write('{:20}\t\t{}\n'.format(key,value))
                    else:
                        f.write('{}\n'.format(key))
                        for ent in value:
                            f.write('{:^20}\t\t{}\n'.format('--',ent))
                f.write('\n\n')
            # Write Associated IP Address
            if self.ip_info:
                f.write('Associated IP Address:\n'+'-'*80+'\n') 
                f.write('{}\n\n'.format(self.ip_info))
            # Write OS Detection
            if self.os_json:
                f.write('OS Detection:\n'+'-'*80+'\n') 
                for key,value in self.os_json.iteritems():
                    f.write('{:20}\t\t{}\n'.format(key,value))
                f.write('\n\n')
                #f.write('{}\n'.format(self.os_info))
            # write Geolocation Info
            if self.geo_json:
                f.write('Geolocation Information:\n'+'-'*80+'\n')    
                for key,value in self.geo_json.iteritems():
                    if not isinstance(value,list):
                        f.write('{:20}\t\t{}\n'.format(key,value))
                    else:
                        f.write('{}\n'.format(key))
                        for ent in value:
                            f.write('{:^20}\t\t{}\n'.format('--',ent))
                f.write('\n\n')
            f.write('='*80+'\n'+'\\/'*40+'\n'+'='*80+'\n'*4)

    def generate_db(self):
        """
        Generate SQLite database containing analysis results

        """
        if self.whois_json:
            new_entry = WhoisInfo(self.ip,self.whois_json)
            self.session.add(new_entry)
            self.session.commit()
        if self.os_json:
            new_entry = OSDetection(self.ip,self.os_json)
            self.session.add(new_entry)
            self.session.commit()
        if self.geo_json:
            new_entry = GeoLocation(self.geo_json)
            self.session.add(new_entry)
            self.session.commit()


    def generate_kml(self):
        """
        Generate KML file with geoLocation Information
        
        """
        if self.geo_json:
            self.kml.newpoint(name=self.hostname, coords=[(self.geo_json['longitude'],self.geo_json['latitude'])])
# ===================  End DomainAnalysis Class  ====================





def main(argv):
    # URL parse
    parser = argparse.ArgumentParser(description='Performs domain name analysis and IP geolocation of the provided list of URLs.')
    parser.add_argument('input_file',nargs='*', help='File contains URL(s) to be analyzed')
    parser.add_argument('-U','--url', nargs='+', help='URL(s) to be analyzed;')
    parser.add_argument('-D','--dbfile',nargs='?',const='output.db', help='Directs the database output to a name of your choice')
    parser.add_argument('-R','--report',nargs='?', const='report.txt', default='report.txt', help='Directs the text report output to a name of your choice')
    parser.add_argument('-K','--kml',nargs='?', const='output.kml', help='Directs the KML output to a name of your choice')
    args = parser.parse_args()

    # Prepare for database output
    session = ''
    if args.dbfile:
        db_name = args.dbfile
        engine = create_engine('sqlite:///'+db_name,echo=False)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()

    # Prepare for KML output
    kml = ''
    if args.kml:
        kml = simplekml.Kml()

    # read URLs from input file(s) and --url parameter
    urls = []
    if args.url:
        urls += args.url
    for fname in args.input_file:
        with open(fname) as f:
            content = f.readlines()
            urls += [line.strip() for line in content]
    if not urls:
        print 'No input!'
        sys.exit()

    # Process for each url
    count = 1
    success = 0
    for url in urls:
        status = 'Processing...  {}/{}'.format(count,len(urls))
        sys.stdout.write(status+'\r')
        sys.stdout.flush()
        count += 1
        if not url:
            continue
        try:
            #Execution for each URL
            da = DomainAnalysis(session,kml,url)
            da.get_whois()
            da.get_ip()
            da.fingerprint_os()
            da.get_geo()
            da.write_report(args.report)
            if args.dbfile:
                da.generate_db()
            if args.kml:
                da.generate_kml()
        except Exception as e:
            print e
            continue
        success += 1 
    
    # write KML file
    if args.kml:
        kml.save(args.kml)

    # End
    print 'Finish. {}/{} Success  \n '.format(success,len(urls))
if __name__ == '__main__':

    main(sys.argv)
