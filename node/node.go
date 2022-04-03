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
	mutex          sync.Mutex
	peers          []NodeAddr
	received_votes int8
	term           int
	log            []NodeLogEntry
	status         string
}

func main() {

	status := NodeStatus{
		peers:          []NodeAddr{},
		received_votes: -1,
		term:           0,
		log:            []NodeLogEntry{},
		status:         "alive",
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
			status.mutex.Lock()
			for _, v := range status.peers {
				fmt.Println("\t" + v.ip + ":" + strconv.Itoa(int(v.port)))
			}
			status.mutex.Unlock()
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
		if status.status == "dead" {
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
	switch msg.msg_type {
	case request_vote:
		status.mutex.Lock()

		status.mutex.Unlock()
	case append_entries:
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
}
