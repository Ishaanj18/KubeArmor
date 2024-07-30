package main

import (
	"context"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type handler interface {
	listContainers(ctx context.Context) ([]types.Container, error)
	close() error
}
