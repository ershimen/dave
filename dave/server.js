var Net = require('net');

const port = 12345;

const server = Net.createServer();

server.listen(port, function() {console.log(`Listening on port ${port}`)})

server.on('connection', function(socket) {
    console.log('New connection');
    socket.on('data', function(buffer) {
        console.log(`Buffer: ${buffer.toString()}`);
        socket.write('Response');
    });
    socket.on('end', function() {
        console.log('Closed connection')
    });
    socket.on('error', function(error) {
        console.log(`Error: ${error}`)
    });
    socket.on('ready', function(){
        console.log("prepared")
    });
    socket.on('lookup', function(){
        console.log("lookup")
    });
});
console.log("tee")
