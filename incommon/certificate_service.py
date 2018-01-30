#!/usr/bin/python
"""Comodo SSL Certificate API client class

API documentation is hosted at:
    https://www.incommon.org/cert/repository/InCommon_CM_SSL_Web_Service_API.pdf

"""
__author__ = "Justin Azoff <jazoff@illinois.edu>, Edward Delaporte <delaport@illinois.edu>, University of Illinois"
__copyright__ = "Copyright (C) 2011-2018 University of Illinois Board of Trustees. All rights reserved."
__license__ = "University of Illinois/NCSA Open Source License"

import suds
from .data import COMODO_SERVER_TYPES, AVAILABLE_CERTIFICATE_TYPES, WEB_SSL_CERT

class CertificateServiceError(Exception):
    pass

class RequestFailedError(CertificateServiceError):
    pass

class NotReadyError(CertificateServiceError):
    pass

def getComodoService(settings):
    """Return a ComodoService instance.
    @param settings - a ConfigParser instance containing the following keys:
    [comodo]
    org_id=...
    api_key=...
    user=...
    password=...
    login_uri=...
    """
    org_id = settings.get('comodo', 'org_id')
    api_key = settings.get('comodo', 'api_key')
    user = settings.get('comodo', 'user')
    password = settings.get('comodo', 'password')
    login_uri = settings.get('comodo', 'login_uri')
    revoke_phrase = settings.get('comodo', 'revoke_phrase')

    service = ComodoSSLService(
        org_id = org_id,
        api_secret_key = api_key,
        user = user,
        password = password,
        login_URI = login_uri,
        revoke_phrase = revoke_phrase,
        )
    return service

SERVER_APACHE = 2
SERVER_IIS    = 14


class ComodoSMIMEService(object):
    """Placeholder --- Not implemented service consumer for the Comodo SMIME certifcate API."""
    def __init__(self, org_id, api_secret_key, user, password, login_URI, revoke_phrase):
        self.WSDL = "https://cert-manager.com/ws/EPKIManager?wsdl"

    def request(self, csr, name, email):
        pass
        #result = self.SOAP.enroll(
        #   data['authData'],
        #   data['orgId'],
        #   data['secretKey'],
        #   data['username'], 
        #   data['email'], 
        #   data['csr'],
        #       )

class ComodoSSLService(object):

    def __init__(self, org_id, api_secret_key, user, password, 
            revoke_phrase, login_URI='InCommon'):
        """
        @org_id Comodo customer ID
                Can be obtained from Admin UI in the
                 'Organization properties' - 'Client Cert' tab.
        @api_secret_key Secret Key for SSL
                Setting in Client Admin UI in 
                'Organization properties' - 'SSL Certificates' tab.
        @user - Comodo username, must have 'Client Cert' role within CCM account.
        @password - Password for the username
        @revoke_phrase - A certificate revocation passphrase. Cannot be left blank!
        @login_URI - Per Comodo API documentation: "URI for logging into account within CCM."
        """
        # Organization identifier. Can be obtained from Admin UI
        #  - Organization properties - Client Cert tab.
        self.OrgID = org_id 

        # Secret Key
        # Setting in Client Admin UI
        # Organization Properties - SSL Certificates
        self.SecretKey = api_secret_key

        self.WSDL = "https://cert-manager.com/ws/EPKIManagerSSL?wsdl"

        self.Client = suds.client.Client(self.WSDL)

        self.RevokePhrase = revoke_phrase

        # self.Client.setLogin(user)
        self.SOAP = self.Client.service
        self.Factory = self.Client.factory
        self.Auth = self.Factory.create('authData')
        # self.Auth.customerLoginUri = "https://cert-manager.com/"
        self.Auth.customerLoginUri = login_URI
        self.Auth.login = user
        self.Auth.password = password
        self.Debug = False

    def getServerType(self, server_type_name):
        '''A bit of a hack to convert server type names into API keys.'''
        return COMODO_SERVER_TYPES.get(server_type_name)

    def request(self, csr, fqdns=[], term='365 days', server_type='Apache-ModSSL', cert_type='InCommon SSL', comments=''):
        """Request a new SSL certificate from Comodo.

        @csr Certificate Signing Request
        @fqdns fully qualified domain names
        @serverType SERVER_APACHE or SERVER_IIS 

        @return Comodo Certificate ID

        """
        serverType = self.getServerType(server_type)

        certType = self.getCertType(cert_type)

        data = {
                'authData':      self.Auth,
                'orgId':         int(self.OrgID),
                'secretKey':     self.SecretKey,
                'csr':           csr,
                'phrase':        self.RevokePhrase,
                'subjAltNames':  ','.join(fqdns),
                'certType':      certType,
                'numberServers': 1,
                'serverType':    serverType,
                'term':          term,
                'comments':      comments,
            }
        # print "Data passed to Enroll: %s" % str(data)

        result = self.SOAP.enroll5(
            data['authData'],
            data['orgId'],
            data['secretKey'],
            data['csr'],
            data['phrase'],
            data['subjAltNames'],
            data['certType'], 
            data['numberServers'],
            data['serverType'],
            data['term'], 
            data['comments'],
        )

        if result < 0:
            self.raiseError(result)
        else:
            return result

    def getCertTypes(self):
        """Returns the certificate types available to the current user."""
        response = self.SOAP.getCustomerCertTypes5(self.Auth)
        status_code = response.statusCode
        self.raiseError(status_code)
        return response.types

    def getCertType(self, cert_type):
        # print "Available certificate types: %s" % str(certTypes)
        for ct in self.getCertTypes():
            if ct.name.strip() == cert_type.strip():
                return ct

        raise Exception("A Comodo API error occurred. Requested certificate type %s is not available." % cert_type)

    def renew(self, certId):
        """Request renewal of an SSL certificate previously issued from Comodo.
        @certId Comodo CCM certificate id
        @return True if the renewal was successfully submitted.
        """
        status_code = self.SOAP.renew(certId)
        if status_code == 0:
            return True
        if status_code == -4:
            raise ValueError("Invalid Comodo Certificate ID: %s" % certId)
        if status_code == -3:
            raise RequestFailedError("Comodo API error. The Comodo service may be down.")
        else:
            self.raiseError(status_code)

    def revoke(self, certId, revokeReason):
        """Request revocation of an SSL certificate previously issued by Comodo.
        @certId Comodo CCM certificate id
        @revokeReason Reason for revocation of this certificate (256 char max)
        @return True if the revocation was successfully submitted.
        """
        if len(revokeReason) > 256:
            raise ValueError("Revocation reason string too long.  256 char max.")
        status_code = self.SOAP.revoke(certId, revokeReason)
        self.raiseError(status_code)
        return status_code == 0

    def collect(self, certId):
        """Collect the SSL certificate from Comodo.
        @certId Comodo CCM certificate id
        """
        # if not self.certReady(certId):
        #   raise NotReadyError("The requested certificate has not been processed yet.") 
        
        response = self.SOAP.collect(
            self.Auth,
            certId,
            formatType = 1
            )
        # print "Debug: API.Collect Response: %s" % str(response)
        status_code = response.statusCode
        self.raiseError(status_code)
        if status_code == 0:
            return (None, None)
        ssl = response.SSL
        # print "Debug: API.Collect SSL object: %s" % str(ssl)
        cert = ssl['certificate']
        renew_id = ssl['renewID']
        return (renew_id, cert)

    def collectRenewed(self, renewId):
        #FIXME: untested, probably broken, return value is NOT the same as collect
        response = self.SOAP.collectRenewed(
            renewId,
            formatType = 1
        )
        status_code = response.statusCode
        self.raiseError(status_code)
        ssl = response.SSL
        cert = ssl['certificate']
        renew_id = ssl['renewID']
        return (renew_id, cert)

    def certReady(self, certId):
        """Return True if the requested SSL certificate is finished processing and available from Comodo.
        @certId Comodo CCM certificate id
        """
        status_code = self.SOAP.getCollectStatus(self.Auth, certId)
        if status_code == -23:
            return False
        self.raiseError(status_code)
        return status_code == 1

    def updateRequesterExt(self, certId, requestors):
        status_code = self.SOAP.updateRequesterExt(self.Auth, certId, requestors)
        self.raiseError(status_code)

    def raiseError(self, result):
        if result >= 0:
            return
        if result < 0 and result > -7:
            raise RequestFailedError("The request could not be processed. (%d)" % result)
        if result == -14:
            raise RequestFailedError("Comodo API error. The Comodo service may be down. (%d)" % result)
        if result == -16 or result == -120:
            raise ValueError("Insufficient privileges.(%d)" % result)
        if result == -20:
            raise RequestFailedError("The certificate request has been rejected.(%d)" % result)
        if result == -21:
            raise RequestFailedError("The certificate has been revoked.(%d)" % result)
        if result == -22:
            raise RequestFailedError("Payment error.(%d)" % result)
        if result == -34:
            raise RequestFailedError("The secret key is invalid.(%d)" % result)
        if result == -40:
            raise RequestFailedError("Invalid Certiticate ID (Order IDs are not Certificate IDs). Certificate IDs are normally 5 characters long and only returned by the API.(%d)" % result)
        if result == -100:
            raise ValueError("Invalid login or password.(%d)" % result)
        if result == -101:
            raise ValueError("Invalid organization credentials.(%d)" % result)
        if result == -110 or result == -111:
            raise ValueError("Illegal domain requested.(%d)" % result)
        raise ValueError("An unknown error occurred. See Comodo API documents for error number %s." % result)
