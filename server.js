var config = require('./config'),
    atob = require('atob'),
    proxy = require('./lib/HTTPClient.js'),
    url = require('url');

var express = require('express'),
    XMLHttpRequest = require("./lib/xmlhttprequest").XMLHttpRequest;

process.on('uncaughtException', function (err) {
  console.log('Caught exception: ' + err);
});

var app = express();

config['idmUrl'] = url.parse(config.account_host)
config['roleRegexp'] = new RegExp(config.idm_role_regexp)

//app.use(express.bodyParser());

app.use (function(req, res, next) {
    var data='';
    req.setEncoding('utf8');
    req.on('data', function(chunk) { 
       data += chunk;
    });

    req.on('end', function() {
        req.body = data;
        next();
    });
});

app.configure(function () {
    "use strict";
    app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
    //app.use(express.logger());
    //app.use(express.static(__dirname + dirName));
    //app.set('views', __dirname + '/../views/');
    //disable layout
    //app.set("view options", {layout: false});
});

app.use(function (req, res, next) {
    "use strict";
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'HEAD, POST, GET, OPTIONS, DELETE');
    res.header('Access-Control-Allow-Headers', 'origin, content-type, X-Auth-Token, Tenant-ID, Authorization');
    //console.log("New Request: ", req.method);
    if (req.method == 'OPTIONS') {
        console.log("CORS request");
        res.statusCode = 200;
        res.header('Content-Length', '0');
        res.send();
        res.end();
    }
    else {
        next();
    }
});
app.set('port', process.env.PORT || 80);

var myToken = undefined;

var authenticate = function(callback, callbackError) {

    var options = {
        host: config.keystone_host,
        port: config.keystone_port,
        path: '/v2.0/tokens',
        method: 'POST',
        headers: {}
    };
    var body = {auth: {passwordCredentials: {username: config.username, password: config.password}}}
    proxy.sendData('http', options, JSON.stringify(body), undefined, callback, callbackError);
};

var checkToken = function(token, callback, callbackError) {

    var options = {
        host: config.keystone_host,
        port: config.keystone_port,
        path: '/v2.0/access-tokens/' + token,
        method: 'GET',
        headers: {'X-Auth-Token': myToken, 'Accept': 'application/json'}
    };
    proxy.sendData('http', options, undefined, undefined, callback, function (status, e) {
        if (status === 401) {

            console.log('Error validating token. Proxy not authorized in keystone. Keystone authentication ...');   
            authenticate (function (status, resp) {

                myToken = JSON.parse(resp).access.token.id;

                console.log('Success authenticating PEP proxy. Proxy Auth-token: ', myToken);
                checkToken(token, callback, callbackError);

            }, function (status, e) {
                console.log('Error in IDM communication ', e);
                callbackError(503, 'Error in IDM communication');
            });
        } else {
            callbackError(status, e);
        }
    });
};

var getIdmUser = function(token, callback, callbackError) {
    var idmUrl = config.idmUrl
    var protocol = idmUrl.protocol.slice(0, -1)
    var options = {
        host: idmUrl.hostname,
        port: idmUrl.port,
        path: "/user?access_token=" + token,
        method: 'GET',
        headers: {'Accept': 'application/json'}
    }

    proxy.sendData(protocol, options, undefined, undefined,
        callback, callbackError);
}

var extractService = function(role) {
    var matched = config.roleRegexp.exec(role.name)
    return matched ? matched[1] : null
}

var isValidUser = function(roles, requestedService) {
    return roles.map(extractService).indexOf(requestedService) != -1
}

var isPrivilegedRole = function(privilegedRoles, role) {
    return privilegedRoles.indexOf(role.name) != -1
}

var isPrivilegedUser = function(privilegedRoles, roles) {
    return roles.some(isPrivilegedRole.bind(null, privilegedRoles))
}

var checkIdmUser = function(requestedService, token, callback, callbackError) {
    getIdmUser(token, 
        function(status, res) {
            var user = JSON.parse(res)
            if (isPrivilegedUser(config.privileged_roles, user.roles) ||
                isValidUser(user.roles, requestedService)) {
                callback(200, res)
            } else {
                callbackError(404, undefined)
            }
        }, 
        callbackError)
}

var getCheckFunction = function(requestedService) {
    return config.check_roles_services 
            ? checkIdmUser.bind(null, requestedService) 
            : checkToken
}

app.all('/*', function(req, res) {
	
	var auth_token = req.headers['x-auth-token'];

    if (auth_token === undefined && req.headers['authorization'] !== undefined) {
        auth_token = atob(req.headers['authorization'].split(' ')[1]);
    }

	if (auth_token === undefined) {
        console.log('Auth-token not found in request header');
        var auth_header = 'IDM uri = ' + config.account_host;
        res.set('WWW-Authenticate', auth_header);
		res.send(401, 'Auth-token not found in request header');
	} else {

        var checkFunction = getCheckFunction(req.headers['fiware-service'])

		checkFunction(auth_token, function (status, resp) {

            var userInfo = JSON.parse(resp);
            console.log('Access-token OK. Redirecting to app.');

            req.headers['X-Nick-Name'] = userInfo.nickName;
            req.headers['X-Display-Name'] = userInfo.displayName;

			var options = {
		        host: config.app_host,
		        port: config.app_port,
		        path: req.url,
		        method: req.method,
		        headers: proxy.getClientIp(req, req.headers)
		    };
		    proxy.sendData('http', options, req.body, res);

		}, function (status, e) {
			if (status === 404 || status === 401) {
                console.log('User access-token not authorized');
                res.send(401, 'User token not authorized');
            } else {
                console.log('Error in IDM communication ', e);
                res.send(503, 'Error in IDM communication');
            }
		});
	}

	
});


if (config.check_roles_services) {
    console.log('Starting PEP proxy.')
    app.listen(app.get('port'));
} else {
    console.log('Starting PEP proxy. Keystone authentication ...');
    authenticate (function (status, resp) {

        myToken = JSON.parse(resp).access.token.id;

        console.log('Success authenticating PEP proxy. Proxy Auth-token: ', myToken);
        app.listen(app.get('port'));

    }, function (status, e) {
        console.log('Error in keystone communication', e);
    });
}

