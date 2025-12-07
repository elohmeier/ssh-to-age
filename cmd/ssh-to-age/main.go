package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	sshage "github.com/Mic92/ssh-to-age"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const privateKeyPEMHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"

func isPrivateKey(data []byte) bool {
	return strings.HasPrefix(string(data), privateKeyPEMHeader)
}

var version = "dev"

type options struct {
	out, in     string
	privateKey  bool
	showVersion bool
	githubUser  string
}

func parseFlags(args []string) options {
	var opts options
	f := flag.NewFlagSet(args[0], flag.ExitOnError)
	f.BoolVar(&opts.privateKey, "private-key", false, "force private key mode (auto-detected by default)")
	f.StringVar(&opts.in, "i", "-", "input path (default: stdin)")
	f.StringVar(&opts.out, "o", "-", "output path (default: stdout)")
	f.StringVar(&opts.githubUser, "github", "", "fetch SSH keys for a GitHub user")
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

func showUsage(programName string) {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", programName)
	fmt.Fprintf(os.Stderr, "Convert SSH Ed25519 keys to age keys.\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -i PATH         input file (default: stdin)\n")
	fmt.Fprintf(os.Stderr, "  -o PATH         output file (default: stdout)\n")
	fmt.Fprintf(os.Stderr, "  -private-key    force private key mode (auto-detected by default)\n")
	fmt.Fprintf(os.Stderr, "  -github USER    fetch SSH keys for a GitHub user\n")
	fmt.Fprintf(os.Stderr, "  -version        show version and exit\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  %s -i ~/.ssh/id_ed25519.pub\n", programName)
	fmt.Fprintf(os.Stderr, "  %s -i ~/.ssh/id_ed25519\n", programName)
	fmt.Fprintf(os.Stderr, "  %s -github Mic92\n", programName)
	fmt.Fprintf(os.Stderr, "  ssh-keyscan host | %s\n", programName)
}

func fetchGitHubKeys(username string) ([]byte, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("GitHub user '%s' not found", username)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
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

	// Show help if invoked interactively with no input
	if opts.in == "-" && opts.githubUser == "" && term.IsTerminal(int(os.Stdin.Fd())) {
		showUsage(args[0])
		return nil
	}

	var sshKey []byte
	var err error

	// Fetch from GitHub if -github flag is set
	if opts.githubUser != "" {
		sshKey, err = fetchGitHubKeys(opts.githubUser)
		if err != nil {
			return err
		}
	} else if opts.in == "-" {
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

	// Auto-detect key type if -private-key not explicitly set
	if isPrivateKey(sshKey) {
		opts.privateKey = true
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
