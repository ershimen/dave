// Titlebar buttons
const { ipcRenderer } = require('electron');
const ipc = ipcRenderer;
btnMini.addEventListener('click', () => {
    ipc.send('minimizeApp');
});
btnMax.addEventListener('click', () => {
    ipc.send('maximizeApp');
});
btnClose.addEventListener('click', () => {
    stop_server();
    udp_client.close();
    ipc.send('closeApp');
});

const dgram = require('dgram');
var udp_client = dgram.createSocket('udp4');

// Log messages
function print(method, s) {
    console.log(`[${method}]: ${s}`);
}

// Network stuff
var network_nodes = new vis.DataSet([]);
var nodes = {};
var network_edges = new vis.DataSet([]);

var container = document.getElementById('mynetwork');

var data = {
    nodes: network_nodes,
    edges: network_edges,
};

var locales = {
    en: {
        edit: 'Edit',
        del: 'Delete selected',
        back: 'Back',
        addNode: 'Add Node',
        addEdge: 'Add Connection',
        editNode: 'Edit Node',
        editEdge: 'Edit Connection',
        addDescription: 'Click in an empty space to place a new node.',
        edgeDescription: 'Click on a node and drag the edge to another node to connect them.',
        editEdgeDescription: 'Click on the control points and drag them to a node to connect to it.',
        createEdgeError: 'Cannot link edges to a cluster.',
        deleteClusterError: 'Clusters cannot be deleted.',
        editClusterError: 'Clusters cannot be edited.'
      }
};

var options = {
    locale: 'en',
    locales: locales,
    nodes: {  
        shape: 'box',
        color: '#C2847A',
        font: {
            align: 'left',
        },
    },
    physics: {
        enabled: false,
    },
    interaction: {
        multiselect: true,
    },
    manipulation: {
        enabled: true,
        addNode: false,
        editEdge: function(data, callback) {
            console.log("Editing node");
        },
        addEdge: function(data, callback) {
            addNetworkEdge(from=data.from, to=data.to);
        },
        editEdge: function(data, callback) {
            console.log("Editing edge");
        },
    },
};

var network = new vis.Network(container, data, options);

function formatLabel(ip, port, realPort, term) {
    if (term == -1) return `ip: ${ip}\nsniffer_port: ${port}\nreal_port: ${realPort}\nterm: unknown`;
    else return `ip: ${ip}\nsniffer_port: ${port}\nreal_port: ${realPort}\nterm: ${term}`;
}

// Manager server
var server = null
var server_running = false
var server_status = document.getElementById('manager-status');
var server_button = document.getElementById('server-button');

function server_toggle() {
    if (server_running) {
        stop_server();
        server_status.innerHTML = 'Offline';
        server_status.style.color = 'red';
        server_button.innerHTML = 'Start UDP Server';
    }
    else {
        start_server();
        server_status.innerHTML = 'Online';
        server_status.style.color = 'green';
        server_button.innerHTML = 'Stop UDP Server';
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

        // Animate message
        console.log(`Edge: ${e}`);
        network.animateTraffic([{
            edge: e,
            trafficSize: 5,
        }]);
        // Update node labels
        var aux_id = `${parsed_msg.SrcIp}:${parsed_msg.SrcPort}`;
        network_nodes.update([{
            id: aux_id,
            label: formatLabel(
                parsed_msg.SrcIp,
                nodes[aux_id].port,
                parsed_msg.SrcPort,
                parsed_msg.Term
            ),
        }]);
    });

    server.on('listening', function() {
        const address = server.address();
        print('start_server', `listening on ${address.address}:${address.port}`);
    });

    server.on('close', function() {
        print('start_server', 'Closed server');
    });

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
    };
    var node_addr = document.getElementById('txt-node-addr');
    new_node = node_addr.value;
    if (new_node == '') {
        print('add_node', 'Empty value');
        return;
    }
    else {
        print('add_node', 'Non empty');
    };
    // Check format
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
    
    network_nodes.update([{
        id: new_id,
        label: new_node,
        label: formatLabel(match.groups.ip, match.groups.port, match.groups.realPort, -1),
    }]);
    network.stabilize(); // Prevent new nodes spawing on top of other nodes
    
    node_addr.value = '';
}

function addNetworkEdge(from, to) {
    let new_edge_id1 = `${from}_${to}`;
    let new_edge_id2 = `${to}_${from}`;
    
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

        // Add both edges
        network_edges.update([
            {id: `${new_edge_id1}`, from: from, to: to},
            {id: `${new_edge_id2}`, from: to, to: from}
        ]);
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

function stop_selected() {
    var node_aux = null;
    for (const node of network.getSelectedNodes()) {
        node_aux = nodes[node];
        udp_client.send('{"type":"STOP", "args":"STOP"}', node_aux.port, node_aux.ip, function (err, bytes) {
            if (!err) {
                print('start_all', `Sent STOP to ${node_aux.ip}:${node_aux.port}`);
            }
        });
    }
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

// Start server initially
start_server();
server_status.innerHTML = 'Online';
server_status.style.color = 'green';
server_button.innerHTML = 'Stop UDP Server';
