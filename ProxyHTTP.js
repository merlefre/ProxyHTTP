var http = require('http');
var fs = require('fs');
var ldap = require('ldapjs');
var url = require('url');
var time = require ('timers');

// Reading of the main configuration file : config.json

var conf = JSON.parse(
  fs.readFileSync('config.json', 'utf8')
);

// Function that write the log inside the file related to right server

var log = function (context, err, code, callback){
  if (context.restricted){
    if (err == "HTTP" && context.login)var data = "" + context.date + "\t" + context.login + "\t" + context.req.method + "\t" + context.req.url + "\t" + code +"\n";
    else var data = "" + context.date + "\t" + err +"\n";
  
    if (data){
      console.log(data);
      fs.appendFileSync(conf[context.conf].logFile, data);
    };
    callback();
  };
};

// Test function for basic http authentication with a fixed login/password defined in config.json

var authentifyDummy =function (context, callback){
  
  context.restricted = true;

  if(!context.req.headers.authorization){
    context.res.statusCode = 401;
    context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
    log(context, "HTTP", 401, function(){});
    context.res.end();
  }else{
    if(context.login === conf[context.conf].authData.login && context.pw === conf[context.conf].authData.pw){
      callback();
    }else{
      context.res.statusCode = 401;
      context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
      log(context, "HTTP", 401, function(){});
      context.res.end();
    }
  }
}

// Cache of recent LDAP bind informations

var servLDAP = {};

// Function that remove old cached informations about LDAP bind

var flush = function(id, server){
  delete servLDAP[server][id];
  if (servLDAP[server] === {}) delete servLDAP[server];
};

// LDAP bind with HTTP basic authentication

var authentifyLDAP =function (context, callback){

  context.restricted = true;

  if(!context.req.headers.authorization){
    context.res.statusCode = 401;
    context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
    log(context, "HTTP", 401, function(){});
    context.res.end();
  }else{
    if (!servLDAP[conf[context.conf].ldap.url] || !servLDAP[conf[context.conf].ldap.url][context.auth]){

      ldapReq = conf[context.conf].ldap.id+ context.login +','+conf[context.conf].ldap.cn; //do not manage more than one dc information
      var serveursLDAP=ldap.createClient({
        'url' : conf[context.conf].ldap.url
      });

      serveursLDAP.bind(ldapReq, context.pw, function(err) { 
        if (!err) {
	        if (!servLDAP[conf[context.conf].ldap.url]) {
            servLDAP[conf[context.conf].ldap.url] ={};
            servLDAP[conf[context.conf].ldap.url][context.auth.toString()] = setTimeout(flush, 600000, [context.auth], [conf[context.conf].ldap.url]);
          }else{
            servLDAP[conf[context.conf].ldap.url][context.auth.toString()] = setTimeout(flush, 600000, [context.auth], [conf[context.conf].ldap.url]);
          }
          serveursLDAP.unbind(function(){
            callback();
          });
        }else{
	        console.log("LDAP error : " + JSON.stringify(err));
          log(context, err, 0, function(){});
          context.res.statusCode = 401;
          context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
          log(context, "HTTP", 401, function(){});
          context.res.end();
        }
      });
    }else{
      clearTimeout(servLDAP[conf[context.conf].ldap.url][context.auth.toString()]);
      servLDAP[conf[context.conf].ldap.url][context.auth.toString()] = setTimeout(flush, 600000, [context.auth], [conf[context.conf].ldap.url]);
      callback();
    }
  }
}

// Function that manage the authorization to access to specific resources defined inside config.json

var AuthorizList =function (context, callback){

  context.restricted = true;

  var idDoc = context.req.url.split('/')[3];
  if(conf[context.conf].restricted[idDoc]){
    if (conf[context.conf].restricted[idDoc].indexOf(context.login) == -1){
      context.res.statusCode = 403;
      log(context, "HTTP", 403, function(){});
      context.res.end("Forbidden");
    } else callback();
  }else{
    callback();
  }
}

// Main proxy function that forward the request and the related answers

var proxyWork = function(context, callback){
   proxyReq = http.request(context.options, function (res){

    if (res.headers.location && conf[context.conf].rewritePath.enable){
      var splitHeaders = res.headers.location.split('/');
      res.headers.location = context.req.headers.origin;
      for (var i = (3 + conf[context.conf].rewritePath.headersOffset); i < splitHeaders.length; i++) {
        res.headers.location = res.headers.location +'/'+ splitHeaders[i];
      }
    }
    context.res.writeHead(res.statusCode, res.headers);
    log(context, "HTTP", res.statusCode, function(){});
    res.on('data',function(chunkOrigin) {
        context.res.write(chunkOrigin);
    });
    res.on('end', function(){
      context.res.end();
    });
  });

  proxyReq.on('error', function(err){
    console.log('problem with the server: ' + JSON.stringify(err));
    context.res.writeHead(504);
    log(context, "HTTP", 504, function(){});
    context.res.end("Gateway Timeout");
  });

  context.req.on('data', function(chunkInit){
    proxyReq.write(chunkInit)
  });

  context.req.on('error', function(err) {
    log(context, err, 0, function(){});
    console.log('problem with request: ' + err.message);
  });

  context.req.on('end', function(){
    proxyReq.end();
    callback();
  });
}

// Function that allow to find the index of the requested server inside config.json

var matching = function(host){ 
  var verif = false;
  var i =0;
  while ((verif == false) && (i < conf.length)){
    var re = new RegExp(conf[i].hostProxy, "i");
    verif = re.test(host);
    if (verif == false)i++;
  };
  if (verif == false ) i = -1;
  return i;
};

// Main HTTP server

http.createServer(function (request, response){
  var index = matching(request.headers.host);
  if(index == -1){
    response.writeHead(404);
    log(context, "HTTP", 404, function(){});
    response.end("Not Found");
  }else{
    var head = JSON.parse(JSON.stringify(request.headers)); 
    if (request.headers.authorization && conf[index].hideAuth) delete head.authorization;
    var options = {
      'host': conf[index].host,
      'port': conf[index].port, 
      'path': conf[index].path + url.parse(request.url).path,
      'method': request.method,
      'headers': head,
      'agent': false
    };

    var context = {
      "req": request,
      "res": response,
      "options": options,
      "conf": index
    };

    if (request.headers.authorization){
      context.auth = request.headers.authorization.split(" ")[1];
      context.login = new Buffer(context.auth, 'base64').toString().split(':')[0];
      context.pw = new Buffer(context.auth, 'base64').toString().split(':')[1];
      context.date = new Date();
    };

    var i=0;
    var breaker = false;
    while(i<conf[index].rules.length && !breaker){
      if(eval(conf[index].rules[i].control)){
        eval(conf[index].rules[i].action);
        breaker = conf[index].rules[i].final;
      }
      i++;
    }
  }
}).listen(1337); // port has to be changed directly inside the code. 
console.log('Server running port 1337');
