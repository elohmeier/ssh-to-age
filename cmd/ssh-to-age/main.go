package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	sshage "github.com/Mic92/ssh-to-age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var version = "dev"

type options struct {
	out, in     string
	privateKey  bool
	showVersion bool
}

func parseFlags(args []string) options {
	var opts options
	f := flag.NewFlagSet(args[0], flag.ExitOnError)
	f.BoolVar(&opts.privateKey, "private-key", false, "convert private key instead of public key")
	f.StringVar(&opts.in, "i", "-", "Input path. Reads by default from standard input")
	f.StringVar(&opts.out, "o", "-", "Output path. Prints by default to standard output")
	f.BoolVar(&opts.showVersion, "version", false, "show version and exit")
	if err := f.Parse(args[1:]); err != nil {
		// should never happen since flag.ExitOnError
		panic(err)
	}

	return opts
}

func writeKey(writer io.Writer, key *string) error {
	if _, err := writer.Write([]byte(*key)); err != nil {
		return err
	}
	_, err := writer.Write([]byte("\n"))
	return err
}

// readPassphraseFromTerminal prompts for a passphrase on the terminal.
// It tries /dev/tty first (works even when stdin is used for key input),
// then falls back to stdin if available.
func readPassphraseFromTerminal() ([]byte, error) {
	// Try /dev/tty first - this works even if stdin is piped
	tty, err := os.Open("/dev/tty")
	if err == nil {
		defer tty.Close()
		if term.IsTerminal(int(tty.Fd())) {
			fmt.Fprint(os.Stderr, "Enter passphrase: ")
			pass, err := term.ReadPassword(int(tty.Fd()))
			fmt.Fprintln(os.Stderr)
			return pass, err
		}
	}

	// Fall back to stdin
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return pass, err
	}

	return nil, errors.New("cannot prompt for passphrase: no terminal available. Set SSH_TO_AGE_PASSPHRASE environment variable")
}

func convertKeys(args []string) error {
	opts := parseFlags(args)

	if opts.showVersion {
		fmt.Println(version)
		return nil
	}

	var sshKey []byte
	var err error
	if opts.in == "-" {
		sshKey, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("error reading stdin: %w", err)
		}
	} else {
		sshKey, err = ioutil.ReadFile(opts.in)
		if err != nil {
			return fmt.Errorf("error reading %s: %w", opts.in, err)
		}
	}

	writer := io.WriteCloser(os.Stdout)
	if opts.out != "-" {
		writer, err = os.Create(opts.out)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", opts.out, err)
		}
		defer writer.Close()
	}
	if opts.privateKey {
		var (
			key *string
			err error
		)

		keyPassphrase := os.Getenv("SSH_TO_AGE_PASSPHRASE")

		key, _, err = sshage.SSHPrivateKeyToAge(sshKey, []byte(keyPassphrase))

		// If key is encrypted and no passphrase was provided, try interactive prompt
		if err != nil {
			var passphraseErr *ssh.PassphraseMissingError
			if errors.As(err, &passphraseErr) && keyPassphrase == "" {
				passphrase, promptErr := readPassphraseFromTerminal()
				if promptErr != nil {
					return fmt.Errorf("failed to read passphrase: %w", promptErr)
				}
				key, _, err = sshage.SSHPrivateKeyToAge(sshKey, passphrase)
			}
		}

		if err != nil {
			return fmt.Errorf("failed to convert private key: %w", err)
		}
		if err := writeKey(writer, key); err != nil {
			return fmt.Errorf("failed to write key: %w", err)
		}
	} else {
		keys := strings.Split(string(sshKey), "\n")
		for _, k := range keys {
			// skip empty lines or comments
			if len(k) == 0 || strings.HasPrefix(k, "#") {
				continue
			}

			key, err := sshage.SSHPublicKeyToAge([]byte(k))
			if err != nil {
				if errors.Is(err, sshage.UnsupportedKeyType) {
					fmt.Fprintf(os.Stderr, "skipped key: %s\n", err)
					continue
				}
				return fmt.Errorf("failed to convert '%s': %w", k, err)
			}
			if err := writeKey(writer, key); err != nil {
				return fmt.Errorf("failed to write key: %w", err)
			}
		}
	}
	return nil
}

func main() {
	if err := convertKeys(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		os.Exit(1)
	}
}
