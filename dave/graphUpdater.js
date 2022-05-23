const { net } = require('electron');
const dgram = require('dgram');

var udp_client = dgram.createSocket('udp4'); // TODO: close this socket

function print(method, s) {
    console.log(`[${method}]: ${s}`);
}

var network_nodes = new vis.DataSet([
    /*
    {id: 1, label: 'Node 1'}, 
    {id: 2, label: 'Node 2'}, 
    {id: 3, label: 'Node 3'},
    */
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
    /*
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
    var node_addr = document.getElementById('txt-node-addr');
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
    //console.log("adding edge");
    let new_edge_id1 = `${from}_${to}`;
    let new_edge_id2 = `${to}_${from}`;
    /*
    console.log(`new_id1: ${new_edge_id1}`);
    console.log(`new_id2: ${new_edge_id2}`);
    console.log(`from: ${from}`);
    console.log(`to: ${to}`);
    */
    if (network_edges.get(new_edge_id1) == null) {

        let from_node = nodes[from];
        let to_node = nodes[to];

        let msg1 = `{"type":"ADD", "args":"ADD ${to_node.ip}:${to_node.realPort}"}`;
        udp_client.send(msg1, from_node.port, from_node.ip, function (err, bytes) {
            if (!err) {
                print('addNetworkEdge', `Sent-1 "${msg1}" to ${from_node.ip}:${from_node.port}`);
            }
        });
        let msg2 = `{"type":"ADD", "args":"ADD ${from_node.ip}:${from_node.realPort}"}`;
        udp_client.send(msg2, to_node.port, to_node.ip, function (err, bytes) {
            if (!err) {
                print('addNetworkEdge', `Sent-2 "${msg2}" to ${to_node.ip}:${to_node.port}`);
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
    var node_aux = null;
    for (const node of network.getSelectedNodes()) {
        node_aux = nodes[node];
        udp_client.send('{"type":"START", "args":"START"}', node_aux.port, node_aux.ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent START to ${node_aux.ip}:${node_aux.port}`);
            }
        });
    }
}

function start_all() {
    var node_aux = null;
    for (var node in nodes) {
        node_aux = nodes[node];
        udp_client.send('{"type":"START", "args":"START"}', node_aux.port, node_aux.ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent START to ${node_aux.ip}:${node_aux.port}`);
            }
        });
    };
}

function stop_all() {
    var node_aux = null;
    for (var node in nodes) {
        node_aux = nodes[node];
        udp_client.send('{"type":"STOP", "args":"STOP"}', node_aux.port, node_aux.ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent STOP to ${node_aux.ip}${node_aux.port}`);
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
