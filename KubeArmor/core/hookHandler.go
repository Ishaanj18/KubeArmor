// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const kubearmorDir = "/var/run/kubearmor"

// ListenToHook starts listening on a UNIX socket and waits for container hooks
func (dm *KubeArmorDaemon) ListenToHook() {
	dm.Logger.Warnf("Hey guys i have entered listentohook")
	if err := os.MkdirAll(kubearmorDir, 0750); err != nil {
		log.Fatal(err)
	}

	listenPath := filepath.Join(kubearmorDir, "ka.sock")
	err := os.Remove(listenPath) 
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}

	socket, err := net.Listen("unix", listenPath)
	dm.Logger.Warnf("Hey guys i have entered ")

	if err != nil {
		
		log.Fatal(err)
	}

	defer socket.Close()
	defer os.Remove(listenPath)
	ready := &atomic.Bool{}

	dm.Logger.Warnf("Hey guys i have entered too")
	for {
		dm.Logger.Warnf("entered the for loop")
		conn, err := socket.Accept()
		dm.Logger.Warnf("connection accepted")
		if err != nil {
			dm.Logger.Warnf("there might be a error ")
			log.Fatal(err)
		}

		go dm.handleConn(conn, ready)
	}

}

// handleConn gets container details from container hooks.
func (dm *KubeArmorDaemon) handleConn(conn net.Conn, ready *atomic.Bool) {
	defer conn.Close()
	buf := make([]byte, 4096)
	dm.Logger.Warnf("entered handleConn")

	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatal(err)
		}

		data := types.HookRequest{}

		err = json.Unmarshal(buf[:n], &data)
		if err != nil {
			log.Fatal(err)
		}

		dm.Logger.Warnf("data received %v", data)
		_, err = conn.Write([]byte("ok"))
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println(err)
			return
		}

		if data.Operation == types.HookContainerCreate {
			dm.Logger.Warnf("Container create called")
			dm.handleContainerCreate(data.Container)
		} 
	}
}
func (dm *KubeArmorDaemon) handleContainerCreate(container types.Container) {
	endpoint := types.EndPoint{}

	dm.Logger.Printf("added %s", container.ContainerID)

	dm.ContainersLock.Lock()
	defer dm.ContainersLock.Unlock()
	if _, ok := dm.Containers[container.ContainerID]; !ok {
		dm.Containers[container.ContainerID] = container
	} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
		c := dm.Containers[container.ContainerID]
		c.MntNS = container.MntNS
		c.PidNS = container.PidNS
		c.AppArmorProfile = container.AppArmorProfile
		dm.Containers[c.ContainerID] = c

		dm.EndPointsLock.Lock()
		for idx, endPoint := range dm.EndPoints {
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
					dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
				}

				if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
					dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
				}

				endpoint = dm.EndPoints[idx]

				break
			}
		}
		dm.EndPointsLock.Unlock()
	}

	if len(dm.OwnerInfo) > 0 {
		container.Owner = dm.OwnerInfo[container.EndPointName]
	}

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
		dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)

		if len(endpoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
			dm.Logger.UpdateSecurityPolicies("ADDED", endpoint)
			if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == types.KubeArmorPolicyEnabled {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
			}
		}
	}
}

