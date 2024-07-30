// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var (
	kubeArmorSocket string
	runtimeSocket   string
	detached        bool
)

func main() {
	flag.StringVar(&kubeArmorSocket, "kubearmor-socket", "/var/run/kubearmor/ka.sock", "KubeArmor socket")
	flag.Parse()

	
	logger := logrus.New()

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	state := specs.State{}
	logger.Info("have i entered here?")
	err = json.Unmarshal(input, &state)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	if err := run(state); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}

func run(state specs.State) error {
	var container types.Container
	operation := types.HookContainerCreate
	// we try to connect to runtime here to make sure the socket is correct
	// before spawning a detached process
	
	container.ContainerID = state.ID
	if state.Status == specs.StateStopped {
		operation = types.HookContainerDelete
		return sendContainer(container, operation)
	}

	var appArmorProfile string

	var isKubeArmor bool
	specBytes, err := os.ReadFile(filepath.Join(state.Bundle, "config.json"))
	if err != nil {
		// revert back to annotations
		containerName := state.Annotations["io.kubernetes.container.name"]
		appArmorProfile = strings.TrimPrefix(
			state.Annotations[fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", containerName)],
			"localhost/",
		)
		isKubeArmor = containerName == "kubearmor"
	} else {
		var spec specs.Spec
		err = json.Unmarshal(specBytes, &spec)
		if err != nil {
			return err
		}
		appArmorProfile = spec.Process.ApparmorProfile // check if Process is nil??
		isKubeArmor = spec.Process.Args[0] == "/KubeArmor/kubearmor"
	}

	if isKubeArmor {
		err = startDetachedProcess()
		if err != nil {
			return err
		}
		
	}
	container = types.Container{
		ContainerID:     state.ID,
		AppArmorProfile: appArmorProfile,
	}
	container.PidNS, container.MntNS = getNS(state.Pid)

	return sendContainer(container, operation)
}

func getNS(pid int) (uint32, uint32) {
	var pidNS uint32
	var mntNS uint32

	nsPath := fmt.Sprintf("/proc/%d/ns", pid)

	pidLink, err := os.Readlink(filepath.Join(nsPath, "pid"))
	if err == nil {
		if _, err := fmt.Sscanf(pidLink, "pid:[%d]\n", &pidNS); err != nil {
			log.Println(err)
		}
	}

	mntLink, err := os.Readlink(filepath.Join(nsPath, "mnt"))
	if err == nil {
		if _, err := fmt.Sscanf(mntLink, "mnt:[%d]\n", &mntNS); err != nil {
			log.Println(err)
		}
	}
	return pidNS, mntNS
}

func sendContainer(container types.Container, operation types.HookOperation) error {
	conn, err := net.Dial("unix", kubeArmorSocket)
	if err != nil {
		return nil
	}

	defer conn.Close()

	data := types.HookRequest{
		Operation: operation,
		Detached:  false,
		Container: container,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	for {
		_, err = conn.Write(dataJSON)
		if err != nil {
			return err
		}
		ack := make([]byte, 1024)
		n, err := conn.Read(ack)
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		response := ack[:n]
		if bytes.Equal(response, []byte("ok")) {
			return nil
		} else {
			time.Sleep(50 * time.Millisecond)
			continue
		}

	}
}


func startDetachedProcess() error {
	args := os.Args[1:]
	args = append(args, "--detached")
	cmd := exec.Command(os.Args[0], args...)
	logFile, err := os.OpenFile("/var/log/ka-hook.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err = cmd.Start()
	if err != nil {
		return err
	}
	return cmd.Process.Release()
}

