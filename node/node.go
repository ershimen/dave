package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
 * States of a node
 */
const (
	follower uint8 = iota
	candidate
	leader
)

// Types of messages
const (
	request_vote uint8 = iota
	append_entries
)

/*
 * Peer
 */
type NodeAddr struct {
	ip   string
	port int16
}

type Entry struct {
}

/*
 * Messages
 */
type NodeMsg struct {
	msg_type uint8
	term     int
	entries  []string
}

/*
 * Log entry
 */
type NodeLogEntry struct {
	msg       string
	timestamp time.Time
}

/*
 * Status of the raft algorithm.
 *	peers: List of peers
 *	received_votes: Number of votes receiver in a votation
 *	term: Numer of the current term
 *	log: List of log entries
 *	status: Status of the raft algorithm. This way goroutines can end
 */
type NodeStatus struct {
	mutex              sync.Mutex
	peers              []NodeAddr
	received_votes     int8
	voted_current_term bool
	term               int
	log                []NodeLogEntry
	raftStatus         uint8
	nodeStatus         string
}

func main() {

	status := NodeStatus{
		peers:              []NodeAddr{},
		received_votes:     -1,
		voted_current_term: false,
		term:               0,
		log:                []NodeLogEntry{},
		raftStatus:         follower,
		nodeStatus:         "alive",
	}

	// Create tcp server
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Error listening")
		os.Exit(1)
	}
	defer l.Close()
	fmt.Println("Listening on port", l.Addr().(*net.TCPAddr).Port)

	// Run response handler
	go listener(l, &status)

	var wg sync.WaitGroup
	wg.Add(2)

	// Run main algorithm
	go raft(&wg, &status)

	// Create cli
	reader := bufio.NewReader(os.Stdin)
	prompt := strconv.Itoa(l.Addr().(*net.TCPAddr).Port) + "> "
	end := false
	regexADD := regexp.MustCompile(`\s*ADD\s*(?P<args>[\w\W]*)`)
	regexSTOP := regexp.MustCompile(`\s*STOP\s*(?P<args>[\w\W]*)`)
	regexPEERS := regexp.MustCompile(`\s*PEERS\s*(?P<args>[\w\W]*)`)

	fmt.Println("Node console")
	for !end {
		fmt.Print(prompt)
		line, _, err := reader.ReadLine()
		if err != nil {
			fmt.Fprint(os.Stderr, "Error reading line from stdin.")
			break
		}
		// ADD command
		if match := regexADD.FindSubmatch(line); len(match) > 0 {
			splittedArgs := strings.Split(string(match[1]), ":")
			switch {
			case len(splittedArgs) != 2:
				fmt.Println("Error: could not read argument string, must have \"ip:port\" format.")
			default:
				ip := splittedArgs[0]
				port := splittedArgs[1]
				nPort, err := strconv.Atoi(port)
				fmt.Println("ip: \"" + ip + "\"")
				fmt.Println("port: \"" + port + "\"")
				if err != nil || len(port) == 0 {
					fmt.Printf("Error: port value \"%s\"is not an integer.\n", port)
				}
				addPeer(&status, ip, nPort)
				fmt.Printf("Added peer %s:%d\n", ip, nPort)
			}
			continue
		}
		// STOP command
		if match := regexSTOP.FindSubmatch(line); len(match) > 0 {
			fmt.Print("Stopping... ")
			end = true
			continue
		}
		// PEERS command
		if match := regexPEERS.FindSubmatch(line); len(match) > 0 {
			fmt.Println("Peers:")
			for _, v := range status.peers {
				fmt.Println("\t" + v.ip + ":" + strconv.Itoa(int(v.port)))
			}
			fmt.Println()
			continue
		}
		fmt.Println("Unrecognized command. Aviable commands are:")
		fmt.Println("\tADD: add peer")
		fmt.Println("\tPEERS: lists peers")
		fmt.Println("\tSTOP: stop node.")
	}
	if end { // porque podria hacer break en readstring()
		wg.Wait()
		fmt.Println("Stopped node.")
	}
}

/*
 * Function that listens for new incoming messages
 */
func listener(l net.Listener, status *NodeStatus) {
	for {
		status.mutex.Lock()
		if status.nodeStatus == "dead" {
			break
		}
		status.mutex.Unlock()
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting")
			os.Exit(1)
		}
		buffer := make([]byte, 2048)
		_, err = conn.Read(buffer)
		if err != nil {
			fmt.Println("Error reading from socket")
			os.Exit(1)
		}
		go reply(conn, buffer, status)
	}
	fmt.Println("Exiting listener goroutine...")
}

/*
 * Function that replies to messages
 */
func reply(conn net.Conn, buffer []byte, status *NodeStatus) {
	var msg NodeMsg
	err := json.Unmarshal(buffer, &msg)
	if err != nil {
		fmt.Println("Error unmarshaling message.")
		return
	}
	status.mutex.Lock()
	defer status.mutex.Unlock()

	switch msg.msg_type {
	// si es una peticion de votacion
	case request_vote:
		switch status.raftStatus {
		case follower:
			// responder con aceptar
			// poner voted_current_term a true
			status.voted_current_term = true
		case candidate:
			// si es candidato, entonces responder solo si el term del mensaje es mayor
			if msg.term > status.term {
				status.raftStatus = follower
				status.term = msg.term
			}
			// si es lider no hace falta responder
		}
	// si es una peticion de entries
	case append_entries:
		switch status.raftStatus {
		case follower:
			status.log = append(status.log, NodeLogEntry{msg: msg.entries[0], timestamp: time.Now()})
		case candidate:
			if msg.term > status.term { // si es candidato y le llega un mensaje con un term superior -> pasar a follower
				status.raftStatus = follower
				status.term = msg.term
			}
		case leader:
			// si le llega un mensaje con term superior entonces pasar a follower de ese term
			if msg.term > status.term {
				status.raftStatus = follower
				status.term = msg.term
			}
		}
	}
}

func addPeer(status *NodeStatus, ip string, port int) {
	status.mutex.Lock()
	status.peers = append(status.peers, NodeAddr{ip, int16(port)})
	status.mutex.Unlock()
}

/*
 *Function that runs the main raft alforithm
 */
func raft(wg *sync.WaitGroup, status *NodeStatus) {
	defer wg.Done()
	fmt.Println("from raft(): ", status.peers)
	electionTimer()
}

func electionTimer() {
	ticker := time.NewTicker(time.Millisecond * 150)
	defer ticker.Stop()
	for {

	}
}
