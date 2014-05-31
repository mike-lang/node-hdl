/**
 * Created by michaellang on 5/24/14.
 */

var dgram = require('dgram');
var net = require('net');

var ENV_FLAG_COMPRESSED = 128; // 0x80
var ENV_FLAG_ENCRYPTED = 64; // 0x40
var ENV_FLAG_TRUNCATED = 32; //0x20
var JAVA_MAXINT = 2^31-1;

function HandleRequest(handle, opCode, authInfo) {
    this._handle = handle;
    this._opCode = opCode;
    this._authInfo = authInfo;
}


function HandleResovler() {

}

HandleResolver.prototype.processRequest = function(request, cb) {
    var self = this;
    function setResponseTimesOfSites(sites) {

    }
    function orderSitesByPreference(sites) {

    }
    function hasInterface() {

    }
    function sendRequestToService(request, sites, cacheResult, cb) {
        var ipv6Sites = getIpSites(sites, IP_VERSION_6);
        var ipv4Sites = getIpSites(sites, IP_VERSION_4);
        setResponseTimesOfSites(sites);
        ipv6Sites = orderSitesByPreference(ipv6Sites);
        ipv4Sites = orderSitesByPreference(ipv4Sites);
        var hasIPv6Interface = hasInterface(IP_VERSION_6);
        var hasIPv4Interface = hasInterface(IP_VERSION_4);

        if (!hasIPv6Interface || ipv6Sites.length == 0) {
            // If there's no IPv6 interface or no IPv6 Sites available
            // go straight to using IPv4

            var resolver4 = new HappyEyeballsResolver(self, ipv4Sites, request, cb,
                primaries, preferredPrimary, 0, false);

            var resolver6 = new HappyEyeballsResolver();

            resolver4.run();
        } else if (!hasIPv4Interface || ipv4Sites.length == 0) {
            // Resolve using IPv6
        } else {
            // Resolve using both and let the first one to respond win??
        }


        // running the request should set the resp property on the resolver
        // do stuff with that here


        // CNRI's client has its caching stuff here

        // There's also a line of code to handle global handle servers going out of service

        // return resp

    }
    var sites = findLocalSites(request);
    sendRequestToService(request, sites, true, cb);
}

HandleResolver.prototype.sendRequestToSite = function(request, site, protocol, cb) {
    this.sendRequestToServerInSiteByProtocol(request, site, null, protocol, cb);
}

HandleResolver.prototype.sendRequestToServerInSiteByProtocol = function(request, site, server, protocol, cb) {

    // request.siteInfoSerial = site.serialNumber;
    request.setSupportedProtocolVersion(site);
    var server = server || site.determineServer(request.handle);
    var response = sendRequestToServerByProtocol(request, server, protocol, cb); // a response and a callback hrmmm...

    // something for handling when "root info" is outdated
    // There is also code here for measuring response time which is put into a table... probably used to determine
    // site preferences

    // also exception handling code that puts values in response time table for use in determining preferences

    return response;
}


HandleResovler.prototype.sendRequestToServerByProtocol = function(request, server, protocolToUse, cb) {
    var self = this;
    function sendRequestToServerByProtocol(request, server, protocol, cb, forceSessionForAdminRequest) {
        if (request.majorProtocolVersion <= 0) {
            request.majorProtocolVersion = COMPATIBILITY_MAJOR_VERSION;
            request.minorProtocolVersion = COMPATIBILITY_MINOR_VERSION;
        }

        var serverInterface = server.interfaceWithProtocol(protocolToUse, request);
        if (!serverInterface) return null;

        // Something about support for "session trackers" and sessions

        // A whole bunch of session setup stuff
        // More session stuff including signing
        var response = sendRequestToInterface(request, server, serverInterface, cb);

        // session timeout stuff

        // auth challenge stuff

        if (response) return response;

        // exception logging stuff that needs to be rewritten because error handling in node is very different
        // from JAVA - the java code throws here though if there was no response, but an exception was caught

        return null;
    }

    sendRequestToServerByProtocol(request, server, protocol, cb, false);
}

HandleResolver.prototype.sendRequestToInterface = function(request, server, serverInterface, cb) {
    if (request.certify && this._checkSignatures) {
        request.serverPubKey = null;
        request.serverPubKeyBytes = server.publicKey;
    }

    var addr = server.getInetAddress();
    var port = serverInterface.port;
    var response;

    switch(serverInterface.protocol) {
        case SP_HDL_UDP:
            response = sendHdlUdpRequest(request, addr, port, cb);
            break;
        case SP_HDL_TCP:
            response = sendHdlTcpRequest(request, addr, port, cb);
            break;
        case SP_HDL_HTTP:
            response = sendHttpRequest(request, addr, port, cb);
            break;
        default:
            // JAVA code throws an exception here
    }

    if (response) {
        if (response.responseCode == RC_ERROR) {
            // JAVA code throws an exception here
        } else if (response.expiration < currentTimeMillis() / 1000) {
            // checks if response is "expired"
            // JAVA code also throws an exception here
        }
    }
    return response;
}

HandleResolver.prototype.sendHdlUdpRequest = function(request, addr, port, cb) {
    function getUdpPacketsForRequest(request, addr, port) {
        //************************************* THIS IS WHERE I LEFT OFF***************************************
        // create envelope
        var protocolMajorVersion;
        var protocolMinorVersion;

        if (request.majorProtocolVersion > 0 && request.minorProtocolVersion >= 0) {
            protocolMajorVersion = request.majorProtocolVersion;
            protocolMinorVersion = request.minorProtocolVersion;
        }

        if (!request.requestId  || request.requestId <= 0) {
            // JAVA Client uses JAVA's SecureRandom class with algorithm SHA1PRNG
            request.requestId = Math.abs(Math.floor(Math.random() * (JAVA_MAXINT + 1)));
        }

        var envelope = new MessageEnvelope(protocolMajorVersion, protocolMinorVersion, request.sessionId,
            request.requestId);

        // Don't forget to set the rest of the envelope pieces!


    }
    // mapLocalAddress ???
    // create socket

    var socket;

    if (net.isIPv4(addr))
        socket = dgram.createSocket('udp4');
    else if (net.isIPv6(addr))
        socket = dgram.createSocket('udp6');
    else {
        // Whoa wut?
        throw new Error('Non IP address in addr parameter');
    }

    // create envelope??  -- original code creates object to receive envelope of response early, uses it after sending
    // the request packets though (of course)

    // there's retry logic here

    var packets = getUdpPacketsForRequest(request, addr, port); // packets should be an array of Buffer objects
}

function HappyEyeballsResolver(handleResolver, sites, request, cb, primaries, preferredPrimary, delayMillis,
    mustWaitForSiblingToProcessPreferredPrimary) {
    this._sites = sites;
    this._resolver = handleResolver;
    this._request = request;
    this._cb = cb;
}

HappyEyeballsResolver.prototype.run = function() {

    function sendRequestToSiteViaProtocol(site, p_index /* an index into the protocols array??  really? */ ) {
        this._resp = this._resolver.sendRequestToSite(this._request, site, this._resolver.preferredProtocols[p_index],
            this._cb);

        if (this._resp) {
            setPreferredPrimaryStatus(site);
            this._publicException = undefined;
        }
    }

    function sendRequestToPreferredPrimary() {
        if (this._preferredPrimary /* && !this._siblingPreferredPrimaryLatch sibling stuff... */) {
            for (var i = 0; i < this._resolver.preferredProtocols.length; i++) {
                sendRequestToSiteViaProtocol(preferredPrimary, i);
                if (this._resp) return;
            }
        }

    }

    function sendRequestAndSetResponseOrPublicException() {
        sendRequestToPreferredPrimary();
        // signal to "sibling" resolver here
        if (!this._resp && !this._interrupted) // Not sure if I will support interupts, but lets leave the hook
            sendRequestToSites();
    }
    if (!this._sites.length) return;

    // multithreading stuff related to "sibling" requests for when both IPv4 & IPv6 requests are going concurrently

    // if (req.completed.get()) return; // ??? - what is this?

    // if (delayMillis > 0 )  // Support for delaying the request before sending it?

    // if (req.completed.get()) return; // ??? - this again...

    sendRequestAndSetResponseOrPublicException(); // The meat!
}

function MessageEnvelope(protocolMajorVersion, protocolMinorVersion, sessionId, requestId) {
    this._protocolMajorVersion = protocolMajorVersion || 0;
    this._protocolMinorVersion = protocolMinorVersion || 0;
    this._sessionId = sessionId || 0;
    this._requestId = requestId;
}

MessageEnvelope.prototype.setMessageId = function(messageId) {
    this._messageId = messageId;
};
MessageEnvelope.prototype.setRequestLength = function(requestLength) {
    this._requestLength = requestLength; // messageLength in the JAVA client code
};
MessageEnvelope.prototype.setCompressedFlag = function(isCompressed) {
    this._isCompressed = isCompressed;
};
MessageEnvelope.prototype.setEncryptedFlag = function(isEncrypted) {
    this._isEncrypted = isEncrypted;
};
MessageEnvelope.prototype.setTruncatedFlag = function(isTruncated) {
    this._isTruncated = isTruncated;
}

MessageEnvelope.prototype.getEncodedBuffer = function() {
    var buffer = new Buffer(20); // Envelope consists of 20 octets

    buffer.writeInt8(this._protocolMajorVersion, 0);
    buffer.writeInt8(this._protocolMinorVersion, 1);
    buffer.writeInt8((this.isCompressed ? ENV_FLAG_COMPRESSED : 0)
        | (this._isEncrypted ? ENV_FLAG_ENCRYPTED : 0)
        | (this._isTruncated ? ENV_FLAG_TRUNCATED : 0), 2);
    buffer.writeInt8(0, 3);
    buffer.writeInt32BE(this._sessionId, 4);
    buffer.writeInt32BE(this._requestId, 8);
    buffer.writeInt32BE(this._messageId, 12);
    buffer.writeInt32BE(this._requestLength, 16);

    return buffer;
}

function AbstractMessage(/* What goes in here?? anything? */) {

}

// Response Codes
AbstractMessage.RC_RESERVED = 0; // Use only for request messages

AbstractMessage.RC_SERVER_BACKUP = 7;

// Op Codes
AbstractMessage.OC_RESOLUTION = 1;

AbstractMessage.prototype.getEncodedMessage() {
    function writeHeader(message, buffer, bodyLength) {
        var writeLocation = 0;
        buffer.writeInt32BE(message.opCode, writeLocation);
        writeLocation += 4;

        if (message.responseCode === AbstractMessage.RC_SERVER_BACKUP && !message.hasEqualOrGreaterVersion(2, 5))
    }
    function encodeResolutionRequest(resolutionRequest) {

    }
    var buffer;
    // Ok, we cache the encoded result
    if (this._encodedMessage) return this._encodedMessage;

    switch(this._responseCode) {
        case AbstractMessage.RC_RESERVED:
            switch(this._opCode) {
                case AbstractMessage.OC_RESOLUTION:
                    buffer = encodeResolutionRequest(this);
                    break;
            }
    }

    if (!buffer) {
        throw new Error("encoding not implemented for type: " + this._opCode);
    }

    return buffer;
}

AbstractMessage.prototype.getEncodedMessageBody = function() {
    if (this._messageBody) return this._messageBody;

}

AbstractMessage.prototype.hasEqualOrGreaterVersion = function(majorVersion, minorVersion) {
    if (this._majorProtocolVersion == 5) return majorVersion == 5 && this._minorProtocolVersion >= minorVersion;
    if (majorVersion == 5) return true;
    if (this._majorProtocolVersion > majorVersion) return true;
    if (this._majorProtocolVersion < majorVersion) return false;
    return this._minorProtocolVersion >= minorVersion;
}
