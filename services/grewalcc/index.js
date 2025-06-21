const {HomeGeneralClient} = require('./home_general_grpc_web_pb.js');
const {HomeGeneralRequest} = require('./home_general_pb.js');

// Use the current page's origin for the client endpoint
const client = new HomeGeneralClient(window.location.origin, null, null); 
const request = new HomeGeneralRequest();

// Set request parameters dynamically
request.setHttpHost(window.location.hostname); 
request.setRemoteIp("?.?.?.?"); // Placeholder - backend should get real IP from headers
request.setUserAgent(navigator.userAgent); 

// Make the gRPC-Web call
client.getHomeGeneral(request, {}, (err, response) => {
    if (err) {
        // Handle errors (display message directly in the body)
        console.error("Error:", err.code, err.message);
        document.body.innerHTML = "<h1>Error</h1><p>" + err.message + " (Code: " + err.code + ")</p>";
    } else {
        // Handle success: Get the HTML string and replace the entire body content
        console.log("Response HTML received. Replacing document.body.innerHTML.");
        document.body.innerHTML = response.getHtmlOutput(); 
    }
});
