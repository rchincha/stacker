package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/sha256-simd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

type generateOptions struct {
	analyze bool
	//noGitignore    bool
	noGoModules   bool
	noGoTransient bool
	scanImages    bool
	name          string // Name to use in the document
	namespace     string
	format        string
	outputFile    string
	configFile    string
	license       string
	//licenseListVer string
	provenancePath string // Path to export the SBOM as provenance statement
	images         []string
	imageArchives  []string
	archives       []string
	files          []string
	directories    []string
	ignorePatterns []string
}

func generateBOM(opts *generateOptions) error {
	newDocBuilderOpts := []spdx.NewDocBuilderOption{spdx.WithFormat(spdx.Format(opts.format))}
	builder := spdx.NewDocBuilder(newDocBuilderOpts...)
	builderOpts := &spdx.DocGenerateOptions{
		Tarballs:         opts.imageArchives,
		Archives:         opts.archives,
		Files:            opts.files,
		Images:           opts.images,
		Directories:      opts.directories,
		Format:           opts.format,
		OutputFile:       opts.outputFile,
		Namespace:        opts.namespace,
		AnalyseLayers:    opts.analyze,
		ProcessGoModules: !opts.noGoModules,
		OnlyDirectDeps:   !opts.noGoTransient,
		ConfigFile:       opts.configFile,
		License:          opts.license,
		//LicenseListVersion: opts.licenseListVer,
		ScanImages: opts.scanImages,
		Name:       opts.name,
	}

	// We only replace the ignore patterns one or more where defined
	if len(opts.ignorePatterns) > 0 {
		builderOpts.IgnorePatterns = opts.ignorePatterns
	}
	doc, err := builder.Generate(builderOpts)
	if err != nil {
		return errors.Errorf("generating doc: %v", err)
	}

	var renderer serialize.Serializer
	if opts.format == "json" {
		renderer = &serialize.JSON{}
	} else {
		renderer = &serialize.TagValue{}
	}

	markup, err := renderer.Serialize(doc)
	if err != nil {
		return errors.Errorf("serializing document: %v", err)
	}
	if opts.outputFile == "" {
	} else {
		if err := os.WriteFile(opts.outputFile, []byte(markup), 0o664); err != nil { //nolint:gosec // G306: Expect WriteFile
			return errors.Errorf("writing SBOM: %v", err)
		}
	}
	// Export the SBOM as in-toto provenance
	if opts.provenancePath != "" {
		if err := doc.WriteProvenanceStatement(
			spdx.DefaultProvenanceOptions, opts.provenancePath,
		); err != nil {
			return errors.Errorf("writing SBOM as provenance statement: %v", err)
		}
	}

	return nil
}

type GenerateBOMOpts struct {
	Path string
	Dest string
}

func GenerateBOM(opts GenerateBOMOpts) error {
	log.SetOutput(io.Discard)
	err := generateBOM(&generateOptions{directories: []string{opts.Path}, outputFile: opts.Dest})
	return err
}

type Entry struct {
	Path     string `yaml:"path" json:"path"`
	Size     int64  `yaml:"size" json:"size"`
	Checksum string `yaml:"checksum" json:"checksum"`
	Mode     string `yaml:"mode" json:"mode"`
}

type Inventory struct {
	Entries []Entry `yaml:"entries" json:"entries"`
}

func GenerateFSInventory(root string) error {
	entries := []Entry{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() &&
			(path == "/proc" ||
				path == "/sys" ||
				path == "/dev") {
			// exclude/skip these dirs
			return filepath.SkipDir
		}

		// skip dirs for generating the inventory
		if info.IsDir() {
			return nil
		}

		entry := Entry{Path: path, Size: info.Size(), Mode: fmt.Sprintf("%#o", info.Mode())}

		// generate checksum
		if info.Mode().IsRegular() {
			fh, err := os.Open(path)
			if err != nil {
				return err
			}
			defer fh.Close()

			hash := sha256.New()
			if _, err := io.Copy(hash, fh); err != nil {
				return err
			}

			entry.Checksum = fmt.Sprintf("sha256:%x", hash.Sum(nil))
		}

		entries = append(entries, entry)

		return nil
	})

	if err != nil {
		return err
	}

	content, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	if err := os.WriteFile("/stacker-artifacts/inventory.json", content, 0640); err != nil {
		return err
	}

	return nil
}
