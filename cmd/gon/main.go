package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"

	"github.com/mitchellh/gon/internal/config"
	"github.com/mitchellh/gon/notarize"
	"github.com/mitchellh/gon/package/dmg"
	"github.com/mitchellh/gon/package/zip"
	"github.com/mitchellh/gon/sign"
	"github.com/mitchellh/gon/staple"
)

// Set by build process
var (
	version string
)

func main() {
	os.Exit(realMain())
}

// item represents an item to notarize.
type item struct {
	// Path is the path to the file to notarize.
	Path string

	// BundleId is the bundle ID to use for this notarization.
	BundleId string

	// Staple is true if we should perform stapling on this file. Not
	// all files support stapling so the default depends on the type of file.
	Staple bool

	// state is the current state of this item.
	State itemState
}

// itemState is the state of an item.
type itemState struct {
	Notarized     bool
	NotarizeError error

	Stapled     bool
	StapleError error
}

// processOptions are the shared options for running operations on an item.
type processOptions struct {
	Config *config.Config
	Logger hclog.Logger

	// Prefix is the prefix string for output
	Prefix string

	// OutputLock protects access to the terminal output.
	//
	// UploadLock protects simultaneous notary submission.
	OutputLock *sync.Mutex
	UploadLock *sync.Mutex
}

// notarize notarize & staples the item.
func (i *item) notarize(ctx context.Context, opts *processOptions) error {
	lock := opts.OutputLock

	// The bundle ID defaults to the root one
	bundleId := i.BundleId
	if bundleId == "" {
		bundleId = opts.Config.BundleId
	}

	// Start notarization
	info, err := notarize.Notarize(ctx, &notarize.Options{
		File:         i.Path,
		BundleId:     bundleId,
		Username:     opts.Config.AppleId.Username,
		Password:     opts.Config.AppleId.Password,
		Provider:     opts.Config.AppleId.Provider,
		Logger:       opts.Logger.Named("notarize"),
		Status:       &statusHuman{Prefix: opts.Prefix, Lock: lock},
		UploadLock:   opts.UploadLock,
		UseRCodeSign: opts.Config.UseRCodeSign,
		Keypath:      opts.Config.Keypath,
	})

	// Save the error state. We don't save the notarization result yet
	// because we don't know it for sure until we download the log file.
	i.State.NotarizeError = err

	// If we had an error, we mention immediate we have an error.
	if err != nil {
		lock.Lock()
		color.New(color.FgRed).Fprintf(os.Stdout, "    %sError notarizing\n", opts.Prefix)
		lock.Unlock()
	}

	// If we have a log file, download it. We do this whether we have an error
	// or not because the log file can contain more details about the error.
	if info != nil && info.LogFileURL != "" {
		opts.Logger.Info(
			"downloading log file for notarization",
			"request_uuid", info.RequestUUID,
			"url", info.LogFileURL,
		)

		log, logerr := notarize.DownloadLog(info.LogFileURL)
		opts.Logger.Debug("log file downloaded", "log", log, "err", logerr)
		if logerr != nil {
			opts.Logger.Warn(
				"error downloading log file, this isn't a fatal error",
				"err", err,
			)

			// If we already failed notarization, just return that error
			if err := i.State.NotarizeError; err != nil {
				return err
			}

			// If it appears we succeeded notification, we make a new error.
			// We can't say notarization is successful without downloading this
			// file because warnings will cause notarization to not work
			// when loaded.
			lock.Lock()
			color.New(color.FgRed).Fprintf(os.Stdout,
				"    %sError downloading log file to verify notarization.\n",
				opts.Prefix,
			)
			lock.Unlock()

			return fmt.Errorf(
				"Error downloading log file to verify notarization success: %s\n\n"+
					"You can download the log file manually at: %s",
				logerr, info.LogFileURL,
			)
		}

		// If we have any issues then it is a failed notarization. Notarization
		// can "succeed" with warnings, but when you attempt to use/open a file
		// Gatekeeper rejects it. So we currently reject any and all issues.
		if len(log.Issues) > 0 {
			var err error

			lock.Lock()
			color.New(color.FgRed).Fprintf(os.Stdout,
				"    %s%d issues during notarization:\n",
				opts.Prefix, len(log.Issues))
			for idx, issue := range log.Issues {
				color.New(color.FgRed).Fprintf(os.Stdout,
					"    %sIssue #%d (%s) for path %q: %s\n",
					opts.Prefix, idx+1, issue.Severity, issue.Path, issue.Message)

				// Append the error so we can return it
				err = multierror.Append(err, fmt.Errorf(
					"%s for path %q: %s",
					issue.Severity, issue.Path, issue.Message,
				))
			}
			lock.Unlock()

			return err
		}
	}

	// If we aren't notarized, then return
	if err := i.State.NotarizeError; err != nil {
		return err
	}

	// Save our state
	i.State.Notarized = true
	lock.Lock()
	color.New(color.FgGreen).Fprintf(os.Stdout, "    %sFile notarized!\n", opts.Prefix)
	lock.Unlock()

	// If we aren't stapling we exit now
	if !i.Staple {
		return nil
	}

	// Perform the stapling
	lock.Lock()
	color.New(color.Bold).Fprintf(os.Stdout, "    %sStapling...\n", opts.Prefix)
	lock.Unlock()
	err = staple.Staple(ctx, &staple.Options{
		File:   i.Path,
		Logger: opts.Logger.Named("staple"),
	})

	// Save our state
	i.State.Stapled = err == nil
	i.State.StapleError = err

	// After we're done we want to output information for this
	// file right away.
	lock.Lock()
	if err != nil {
		color.New(color.FgRed).Fprintf(os.Stdout, "    %sNotarization succeeded but stapling failed\n", opts.Prefix)
		lock.Unlock()
		return err
	}
	color.New(color.FgGreen).Fprintf(os.Stdout, "    %sFile notarized and stapled!\n", opts.Prefix)
	lock.Unlock()

	return nil
}

// String implements Stringer
func (i *item) String() string {
	result := i.Path
	switch {
	case i.State.Notarized && i.State.Stapled:
		result += " (notarized and stapled)"

	case i.State.Notarized:
		result += " (notarized)"
	}

	return result
}

// statusHuman implements notarize.Status and outputs information to
// the CLI for human consumption.
type statusHuman struct {
	Prefix string
	Lock   *sync.Mutex

	lastStatus string
}

func (s *statusHuman) Submitting() {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	color.New().Fprintf(os.Stdout, "    %sSubmitting file for notarization...\n", s.Prefix)
}

func (s *statusHuman) Submitted(uuid string) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	color.New().Fprintf(os.Stdout, "    %sSubmitted. Request UUID: %s\n", s.Prefix, uuid)
	color.New().Fprintf(
		os.Stdout, "    %sWaiting for results from Apple. This can take minutes to hours.\n", s.Prefix)
}

func (s *statusHuman) Status(info notarize.Info) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if info.Status != s.lastStatus {
		s.lastStatus = info.Status
		color.New().Fprintf(os.Stdout, "    %sStatus: %s\n", s.Prefix, info.Status)
	}
}

// statusPrefixList takes a list of items and returns the prefixes to use
// with status messages for each. The returned slice is guaranteed to be
// allocated and the same length as items.
func statusPrefixList(items []*item) []string {
	// Special-case: for lists of one, we don't use any prefix at all.
	if len(items) == 1 {
		return []string{""}
	}

	// Create a list of basenames and also keep track of max length
	result := make([]string, len(items))
	max := 0
	for idx, f := range items {
		result[idx] = filepath.Base(f.Path)
		if l := len(result[idx]); l > max {
			max = l
		}
	}

	// Pad all the strings to the max length
	for idx, _ := range result {
		result[idx] += strings.Repeat(" ", max-len(result[idx]))
		result[idx] = fmt.Sprintf("[%s] ", result[idx])
	}

	return result
}

var _ notarize.Status = (*statusHuman)(nil)

func realMain() int {
	// Look for version
	for _, v := range os.Args[1:] {
		v = strings.TrimLeft(v, "-")
		if v == "v" || v == "version" {
			if version == "" {
				version = "dev"
			}

			fmt.Printf("version %s\n", version)
			return 0
		}
	}

	var logLevel string
	var logJSON bool
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.BoolVar(&logJSON, "log-json", false, "Output logs in JSON format for machine readability.")
	flags.StringVar(&logLevel, "log-level", "", "Log level to output. Defaults to no logging.")
	flags.Parse(os.Args[1:])
	args := flags.Args()

	// Build a logger
	logOut := ioutil.Discard
	if logLevel != "" {
		logOut = os.Stderr
	}
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.LevelFromString(logLevel),
		Output:     logOut,
		JSONFormat: logJSON,
	})

	// We expect a configuration file
	if len(args) != 1 {
		fmt.Fprintf(os.Stdout, color.RedString("❗️ Path to configuration expected.\n\n"))
		printHelp(flags)
		return 1
	}

	// Parse the configuration
	cfg, err := config.ParseFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stdout, color.RedString("❗️ Error loading configuration:\n\n%s\n", err))
		return 1
	}

	// The files to notarize should be added to this. We'll submit one notarization
	// request per file here.
	var items []*item

	// A bunch of validation
	if len(cfg.Source) > 0 {
		if cfg.BundleId == "" {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `bundle_id` configuration required with `source` set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"When you set the `source` configuration, you must also specify the\n"+
					"`bundle_id` that will be used for packaging and notarization.\n")
			return 1
		}

		if cfg.Sign == nil {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `sign` configuration required with `source` set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"When you set the `source` configuration, you must also specify the\n"+
					"`sign` configuration to sign the input files.\n")
			return 1
		}
	} else {
		if len(cfg.Notarize) == 0 {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No source files specified\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"Your configuration had an empty 'source' and empty 'notarize' values. This must be populated with\n"+
					"at least one file to sign, package, and notarize.\n")
			return 1
		}

		if cfg.Zip != nil {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `zip` can only be set while `source` is also set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"Zip packaging is only supported when `source` is specified. This is\n"+
					"because the `zip` option packages the source files. If there are no\n"+
					"source files specified, then there is nothing to package.\n")
			return 1
		}

		if cfg.Dmg != nil {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout,
				"❗️ `dmg` can only be set while `source` is also set\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"Dmg packaging is only supported when `source` is specified. This is\n"+
					"because the `dmg` option packages the source files. If there are no\n"+
					"source files specified, then there is nothing to package.\n")
			return 1
		}
	}

	// Notarize is an alternative to "Source", where you specify
	// a single .pkg or .zip that is ready for notarization and stapling
	if len(cfg.Notarize) > 0 {
		for _, c := range cfg.Notarize {
			items = append(items, &item{
				Path:     c.Path,
				BundleId: c.BundleId,
				Staple:   c.Staple,
			})
		}
	}

	// If not specified in the configuration, we initialize a new struct that we'll
	// load with values from the environment.
	if cfg.AppleId == nil {
		cfg.AppleId = &config.AppleId{}
	}
	if cfg.AppleId.Username == "" {
		appleIdUsername, ok := os.LookupEnv("AC_USERNAME")
		if !ok {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No apple_id username provided\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"An Apple ID username must be specified in the `apple_id` block or\n"+
					"it must exist in the environment as AC_USERNAME,\n"+
					"otherwise we won't be able to authenticate with Apple to notarize.\n")
			return 1
		}

		cfg.AppleId.Username = appleIdUsername
	}

	if cfg.AppleId.Password == "" {
		if _, ok := os.LookupEnv("AC_PASSWORD"); !ok {
			color.New(color.Bold, color.FgRed).Fprintf(os.Stdout, "❗️ No apple_id password provided\n")
			color.New(color.FgRed).Fprintf(os.Stdout,
				"An Apple ID password (or lookup directive) must be specified in the\n"+
					"`apple_id` block or it must exist in the environment as AC_PASSWORD,\n"+
					"otherwise we won't be able to authenticate with Apple to notarize.\n")
			return 1
		}

		cfg.AppleId.Password = "@env:AC_PASSWORD"
	}
	if cfg.AppleId.Provider == "" {
		cfg.AppleId.Provider = os.Getenv("AC_PROVIDER")
	}

	// If we're in source mode, then sign & package as configured
	if len(cfg.Source) > 0 {
		if cfg.Sign != nil {
			// Perform codesigning
			color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Signing files...\n", iconSign)
			err = sign.Sign(context.Background(), &sign.Options{
				Files:        cfg.Source,
				Identity:     cfg.Sign.ApplicationIdentity,
				Entitlements: cfg.Sign.EntitlementsFile,
				Logger:       logger.Named("sign"),
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error signing files:\n\n%s\n", err))
				return 1
			}
			color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "    Code signing successful\n")
		}

		// Create a zip
		if cfg.Zip != nil {
			color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Creating Zip archive...\n", iconPackage)
			err = zip.Zip(context.Background(), &zip.Options{
				Files:      cfg.Source,
				OutputPath: cfg.Zip.OutputPath,
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error creating zip archive:\n\n%s\n", err))
				return 1
			}
			color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "    Zip archive created with signed files\n")

			// Queue to notarize
			items = append(items, &item{Path: cfg.Zip.OutputPath})
		}

		// Create a dmg
		if cfg.Dmg != nil && cfg.Sign != nil {
			// First create the dmg itself. This passes in the signed files.
			color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Creating dmg...\n", iconPackage)
			color.New().Fprintf(os.Stdout, "    This will open Finder windows momentarily.\n")
			err = dmg.Dmg(context.Background(), &dmg.Options{
				Files:      cfg.Source,
				OutputPath: cfg.Dmg.OutputPath,
				VolumeName: cfg.Dmg.VolumeName,
				Logger:     logger.Named("dmg"),
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error creating dmg:\n\n%s\n", err))
				return 1
			}
			color.New().Fprintf(os.Stdout, "    Dmg file created: %s\n", cfg.Dmg.OutputPath)

			// Next we need to sign the actual DMG as well
			color.New().Fprintf(os.Stdout, "    Signing dmg...\n")
			err = sign.Sign(context.Background(), &sign.Options{
				Files:    []string{cfg.Dmg.OutputPath},
				Identity: cfg.Sign.ApplicationIdentity,
				Logger:   logger.Named("dmg"),
			})
			if err != nil {
				fmt.Fprintf(os.Stdout, color.RedString("❗️ Error signing dmg:\n\n%s\n", err))
				return 1
			}
			color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "    Dmg created and signed\n")

			// Queue to notarize
			items = append(items, &item{Path: cfg.Dmg.OutputPath, Staple: true})
		}
	}

	// If we have no items to notarize then its probably an error in the configuration.
	if len(items) == 0 {
		color.New(color.Bold, color.FgYellow).Fprintf(os.Stdout, "\n⚠️  No items to notarize\n")
		color.New(color.FgYellow).Fprintf(os.Stdout,
			"You must specify a 'notarize' section or a 'source' section plus a 'zip' or 'dmg' section "+
				"in your configuration to enable packaging and notarization. Without these sections, gon\n"+
				"will only sign your input files in 'source'.\n")
		return 0
	}

	// Notarize
	color.New(color.Bold).Fprintf(os.Stdout, "==> %s  Notarizing...\n", iconNotarize)
	if len(items) > 1 {
		color.New().Fprintf(os.Stdout, "    Files will be notarized concurrently to optimize queue wait\n")
	}
	for _, f := range items {
		color.New().Fprintf(os.Stdout, "    Path: %s\n", f.Path)
	}

	// Build our prefixes
	prefixes := statusPrefixList(items)

	// Start our notarizations
	var wg sync.WaitGroup
	var lock, uploadLock sync.Mutex
	var totalErr error
	for idx := range items {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			err := items[idx].notarize(context.Background(), &processOptions{
				Config:     cfg,
				Logger:     logger,
				Prefix:     prefixes[idx],
				OutputLock: &lock,
				UploadLock: &uploadLock,
			})

			if err != nil {
				lock.Lock()
				defer lock.Unlock()
				totalErr = multierror.Append(totalErr, err)
			}
		}(idx)
	}

	// Wait for notarization to happen
	wg.Wait()

	// If totalErr is not nil then we had one or more errors.
	if totalErr != nil {
		fmt.Fprintf(os.Stdout, color.RedString("\n❗️ Error notarizing:\n\n%s\n", totalErr))
		return 1
	}

	// Success, output all the files that were notarized again to remind the user
	color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "\nNotarization complete! Notarized files:\n")
	for _, f := range items {
		color.New(color.FgGreen).Fprintf(os.Stdout, "  - %s\n", f.String())
	}

	return 0
}

func printHelp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stdout, strings.TrimSpace(help)+"\n\n", os.Args[0])
	fs.PrintDefaults()
}

const help = `
gon signs, notarizes, and packages binaries for macOS.

Usage: %[1]s [flags] CONFIG

A configuration file is required to use gon. If a "-" is specified, gon
will attempt to read the configuration from stdin. Configuration is in HCL
or JSON format. The JSON format makes it particularly easy to machine-generate
the configuration and pass it into gon.

For example configurations as well as full help text, see the README on GitHub:
http://github.com/mitchellh/gon

Flags:
`

const iconSign = `✏️`
const iconPackage = `📦`
const iconNotarize = `🍎`
