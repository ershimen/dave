const { profileEnd } = require('console');
const { net } = require('electron');
const dgram = require('dgram');

function print(method, s) {
    console.log(`[${method}]: ${s}`);
}

var network_nodes = new vis.DataSet([]);

var nodes = {};
var current_node_id = 0;

/*
for (var i=0; i<6; i++) {
    nodes.add({id: i, label: `Node ${i}`});
    n_nodes++;
}
*/

var network_edges = new vis.DataSet([
    /*
    {from: 1, to: 3},
    {from: 1, to: 2},
    {from: 2, to: 4},
    {from: 2, to: 5}
    */
]);

// create a network
var container = document.getElementById('mynetwork');

// provide the data in the vis format
var data = {
    nodes: network_nodes,
    edges: network_edges,
};
var options = {
    physics: {
        enabled: false,
    }
};

// initialize your network!
var network = new vis.Network(container, data, options);

var server = null

function updateGraph(msg) {
    switch (msg["type"]) {
        default:
            break;
    }
}

function start_server() {
    const dgram = require('node:dgram');
    server = dgram.createSocket('udp4');

    server.on('error', function(err) {
        print('start_server', err.stack)
        server.close();
    });

    server.on('message', function(msg, rinfo) {
        print('start_server', `msg from ${rinfo.address}:${rinfo.port}\n${msg}`);
        var parsed_msg = JSON.parse(msg);
        updateGraph(parsed_msg);
    });

    server.on('listening', function() {
        const address = server.address();
        print('start_server', `listening on ${address.address}:${address.port}`);
    })

    server.on('close', function() {
        print('start_server', 'Closed server');
    })

    server.bind(3333); // random port
}

function stop_server() {
    if (server != null) {
        print('stop_server', 'Closing server...');
        server.close();
        print('stop_server', 'Server closed');
    }
    else {
        print('stop_server', 'Not started');
    }
}

function add_node() {
    if (network == null) {
        return;
    }
    var node_addr = document.getElementById('node_addr');
    new_node = node_addr.value;
    if (new_node == '') {
        print('add_node', 'Empty value');
        return;
    }
    else {
        print('add_node', 'Non empty');
    }
    
    var match = new_node.match(/(?<ip>[.\w]+):(?<port>\d+)/);

    if (match == null) {
        print('add_node', 'Not ip:port format');
        return;
    }

    nodes[current_node_id] = {
        ip: match.groups.ip,
        port: parseInt(match.groups.port),
        process: null,
    };

    print('add_node', `added node: ${JSON.stringify(nodes[current_node_id])}`);
    
    network_nodes.add({id: current_node_id, label: new_node});
    network.stabilize();
    current_node_id++;
    node_addr.value = '';
}

function start_all() {
    for (var node in nodes) {
        var client = dgram.createSocket('udp4');
        client.send('{"type":"START", "args":"START"}', nodes[node].port, nodes[node].ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent START to ${nodes[node].ip}`);
                client.close();
            }
        });
    };
}
/*
function start() {
    console.log("aaaaa");

    const { exec, ChildProcess } = require('child_process');
   
    const ls = exec('dir', function (error, stdout, stderr) {
      if (error) {
        console.log(error.stack);
        console.log('Error code: ' + error.code);
        console.log('Signal received: ' + error.signal);
      }
      console.log('Child Process STDOUT: ' + stdout);
      console.log('Child Process STDERR: ' + stderr);
    });
    
    ls.on('exit', function (code) {
      console.log('Child process exited with exit code ' + code);
    });

}

function start_raft() {
    console.log("start_bg");
    var spawn = require('child_process').spawn;

    var process = spawn('go', ['run', '../node/node.go']);

    process.stdout.setEncoding('utf-8');
    process.stdout.on('data', function(data) {
        console.log(data);
    });

    process.on('close', function(code) {
        console.log('exit:' + code);
    })

    return process;
}

var process = null;

function start_bg() {
    process = start_raft();
}

function send_start() {
    if (process != null) {
        console.log("sending start...");
        process.stdin.write("START\n");
    }
    else {
        console.log("is null");
    }
}

*/

