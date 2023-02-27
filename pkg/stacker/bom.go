package stacker

import (
	"fmt"
	"os"

	"stackerbuild.io/stacker/pkg/container"
	"stackerbuild.io/stacker/pkg/log"
	"stackerbuild.io/stacker/pkg/types"
)

func GenerateLayerArtifacts(sc types.StackerConfig, storage types.Storage, l types.Layer, tag string) error {
	name, cleanup, err := storage.TemporaryWritableSnapshot(tag)
	if err != nil {
		return err
	}
	defer cleanup()

	c, err := container.New(sc, name)
	if err != nil {
		return err
	}
	defer c.Close()

	err = SetupBuildContainerConfig(sc, storage, c, tag)
	if err != nil {
		log.Errorf("build container %v", err)
		return err
	}

	err = SetupLayerConfig(sc, c, l, tag)
	if err != nil {
		return err
	}

	binary, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return err
	}

	if err := c.BindMount(binary, "/static-stacker", ""); err != nil {
		return err
	}

	cmd := fmt.Sprintf("/static-stacker --oci-dir %s --roots-dir %s --stacker-dir %s --storage-type %s --internal-userns",
		sc.OCIDir, sc.RootFSDir, sc.StackerDir, sc.StorageType)

	if sc.Debug {
		cmd += " --debug"
	}

	cmd += " internal-go"

	source := "/usr/lib/"
	dest := fmt.Sprintf("/stacker-artifacts/%s", "libs.spdx")
	cmd += fmt.Sprintf(" bom %s %s", source, dest)
	err = c.Execute(cmd, os.Stdin)
	if err != nil {
		return err
	}

	return nil
}
