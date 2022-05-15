const { net } = require('electron');
const dgram = require('dgram');

var udp_client = dgram.createSocket('udp4'); // TODO: close this socket

function print(method, s) {
    console.log(`[${method}]: ${s}`);
}

var network_nodes = new vis.DataSet([
    {id: 1, label: 'Node 1'}, 
    {id: 2, label: 'Node 2'}, 
    {id: 3, label: 'Node 3'},
]);


var nodes = {};

var current_node_id = 4;

/*
for (var i=0; i<6; i++) {
    nodes.add({id: i, label: `Node ${i}`});
    n_nodes++;
}
*/

var network_edges = new vis.DataSet([
    {id:1, from:1, to:1}, 
    {id:2, from:2, to:1},
    {id:3, from:2, to:3},
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
    },
    manipulation: {
        enabled: true,
        addNode: function(data, callback) {
            console.log("adding node");
            network_nodes.add({id: current_node_id, label: current_node_id})
            current_node_id++;
        },
        editEdge: function(data, callback) {
            console.log("editing node");

        },
        addEdge: function(data, callback) {
            addNetworkEdge(from=data.from, to=data.to);
            //callback(data);
        },
        editEdge: function(data, callback) {
            console.log("editing edge");
        },
    }
};

// initialize your network!
var network = new vis.Network(container, data, options);

var server = null
var server_running = false

function updateGraph(msg) {
    switch (msg["type"]) {
        default:
            break;
    }
}

function start_server() {
    if (server_running) {
        print('start_server', 'Server already running');
        return;
    }
    server = dgram.createSocket('udp4');

    server.on('error', function(err) {
        print('start_server', err.stack)
        server.close();
    });

    server.on('message', function(msg, rinfo) {
        print('start_server', `msg from ${rinfo.address}:${rinfo.port}\n${msg}`);
        var parsed_msg = JSON.parse(msg);
        var e = `${parsed_msg.SrcIp}:${parsed_msg.SrcPort}_${parsed_msg.DstIp}:${parsed_msg.DstPort}`
        // if (network_edges.get(e) == null) { // probar en el sentido contrario
        //     e = `${parsed_msg.DstIp}:${parsed_msg.DstPort}_${parsed_msg.SrcIp}:${parsed_msg.SrcPort}`
        // }
        console.log(`Edge: ${e}`);
        network.animateTraffic([{
            edge: e,
            trafficSize: 4,
        }]);
        updateGraph(parsed_msg);
    });

    server.on('listening', function() {
        const address = server.address();
        print('start_server', `listening on ${address.address}:${address.port}`);
    })

    server.on('close', function() {
        print('start_server', 'Closed server');
    })

    server.bind(3333);
    server_running = true;
}

function stop_server() {
    if (server_running) {
        print('stop_server', 'Closing server...');
        server.close();
        print('stop_server', 'Server closed');
        server_running = false;
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
    
    var match = new_node.match(/(?<ip>[.\w]+):(?<port>\d+):(?<realPort>\d+)/);

    if (match == null) {
        print('add_node', 'Not ip:port:port format');
        return;
    }
    
    var new_id = `${match.groups.ip}:${match.groups.realPort}`; 
    nodes[new_id] = {
        ip: match.groups.ip,
        port: parseInt(match.groups.port),
        realPort: parseInt(match.groups.realPort),
        process: null,
    };

    print('add_node', `added node: ${JSON.stringify(nodes[new_id])}`);
    
    network_nodes.add({id: new_id, label: new_node});
    //network_edges.add({id: current_node_id, from: current_node_id, to: current_node_id})
    network.stabilize();
    //current_node_id++;
    node_addr.value = '';
}

function addNetworkEdge(from, to) {
    console.log("adding edge");
    let new_edge_id1 = `${from}_${to}`;
    let new_edge_id2 = `${to}_${from}`;
    console.log(`new_id: ${new_edge_id1}`);
    if (network_edges.get(new_edge_id1) == null) {

        let from_node = nodes[from];
        let to_node = nodes[to];

        let msg = `{"type":"ADD", "args":"ADD ${to_node.ip}:${to_node.realPort}"}`;
        udp_client.send(msg, from_node.port, from_node.ip, function (err, bytes) {
            if (!err) {
                print('addNetworkEdge', `Sent "${msg}" to ${from_node.ip}:${from_node.port}`);
            }
        });
        msg = `{"type":"ADD", "args":"ADD ${from_node.ip}:${from_node.realPort}"}`;
        udp_client.send(msg, to_node.port, to_node.ip, function (err, bytes) {
            if (!err) {
                print('addNetworkEdge', `Sent "${msg}" to ${to_node.ip}:${to_node.port}`);
            }
        });

        network_edges.add({
            id: `${new_edge_id1}`,
            from: from,
            to: to,
            label: `${new_edge_id1}`,
        });
        network_edges.add({
            id: `${new_edge_id2}`,
            from: to,
            to: from,
            label: `${new_edge_id2}`,
        });
        

    }
    else {
        console.log('Edge already exists');
    }
}

function start_selected() {
    for (const node of network.getSelectedNodes()) {
        udp_client.send('{"type":"START", "args":"START"}', nodes[node].port, nodes[node].ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent START to ${nodes[node].ip}`);
            }
        });
    }
}

function start_all() {
    for (var node in nodes) {
        udp_client.send('{"type":"START", "args":"START"}', nodes[node].port, nodes[node].ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent START to ${nodes[node].ip}`);
            }
        });
    };
}

function stop_all() {
    for (var node in nodes) {
        udp_client.send('{"type":"STOP", "args":"STOP"}', nodes[node].port, nodes[node].ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent STOP to ${nodes[node].ip}`);
            }
        });
    };
}

function clickMe() {
    // **************************************
    // Here is the code for animation
    //
    network.animateTraffic([
        {edge:current_node_id-1},                           // specify forward animation with traffic size=1
        {edge:2, trafficSize:2},            // specify the size of traffic (circle animated)
        {edge:3, trafficSize:5, isBackward: true}   // animates the traffic backward on the edge
    ]);
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

