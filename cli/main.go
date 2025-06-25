package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/zytekaron/galois-go"
	"github.com/zytekaron/shamir-go"
)

var fs = NewFlagSet()

func init() {
	fs.AddFlag("input", "i", "Input file", true)
	fs.AddFlag("output", "o", "Output file", true)
	fs.AddFlag("count", "n", "Number of shares to generate in total", true)
	fs.AddFlag("threshold", "k", "Number of shares required to recover secret", true)
	fs.AddFlag("tagged", "t", "Enable this option if intending to use this tool's prefix tagging scheme for integrity verification", false)
	fs.AddFlag("poly", "P", "The hex polynomial to use for the Galois field (default PolyAES; 0x11B)", true)
	fs.AddFlag("gen", "G", "The hex generator to use for the Galois field (default GenAES; 0x03)", true)

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatalln("error parsing args:", err)
	}
}

func main() {
	if len(fs.RemainingArgs) == 0 {
		log.Fatalln("hungry...want more args")
	}

	command := fs.RemainingArgs[0]
	args := fs.RemainingArgs[1:]

	var err error
	switch command {
	case "help":
		help()
	case "split":
		err = split(args)
	case "combine":
		err = combine(args)
	default:
		if command == "" {
			log.Fatalln("missing subcommand")
		}
		log.Fatalln("missing subcommand")
	}
	if err != nil {
		log.Fatalln("error in op "+command+":", err)
	}
}

func help() {
	// todo
}

func split(args []string) error {
	n, err := strconv.Atoi(fs.ParsedArgs["count"])
	if err != nil {
		return fmt.Errorf("error parsing count: %w", err)
	}
	k, err := strconv.Atoi(fs.ParsedArgs["threshold"])
	if err != nil {
		return fmt.Errorf("error parsing threshold: %w", err)
	}
	// if either poly or gen is set, attempt to parse both.
	field := shamir.GaloisField
	if fs.ParsedArgs["poly"] != "" || fs.ParsedArgs["gen"] != "" {
		poly, err := strconv.ParseInt(fs.ParsedArgs["poly"], 0, 64)
		if err != nil {
			return fmt.Errorf("error parsing polynomial: %w", err)
		}
		gen, err := strconv.ParseInt(fs.ParsedArgs["gen"], 0, 64)
		if err != nil {
			return fmt.Errorf("error parsing generator: %w", err)
		}
		field = galois.New256(uint16(poly), byte(gen))
	}

	// read in the secret

	var input io.Reader
	inputFile := fs.ParsedArgs["input"]
	switch inputFile {
	// the input flag is empty: use remaining arguments, or stdin if none
	case "":
		if len(args) == 0 {
			input = os.Stdin
		} else {
			joined := strings.Join(args, " ")
			input = strings.NewReader(joined)
		}
	// the input flag is -/0/stdio/stdin: use stdin
	case "-", "0", "std", "stdio", "stdin":
		input = os.Stdin
	// the input flag is a file name: open the file
	default:
		file, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("error opening input file: %w", err)
		}
		defer file.Close()
		input = file
	}

	secret, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	// split the secret with shamir

	var shares map[byte][]byte
	if fs.ParsedArgs["tagged"] == "" {
		shares, err = shamir.SplitWithField(field, secret, byte(k), byte(n))
		if err != nil {
			return fmt.Errorf("error splitting secret: %w", err)
		}
	} else {
		shares, err = shamir.SplitTaggedWithField(field, secret, byte(k), byte(n))
		if err != nil {
			return fmt.Errorf("error splitting secret: %w", err)
		}
	}

	nameOption := fs.ParsedArgs["output"]
	nameOptionVar := strings.Contains(nameOption, "{i}") || strings.Contains(nameOption, "{o}")

	// open writers for each share
	for i, share := range shares {
		name := nameOption
		if nameOptionVar {
			name = strings.ReplaceAll(name, "{i}", strconv.Itoa(int(i)))
		} else {
			name += strconv.Itoa(int(i))
		}

		outFile, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("error creating output file '%s': %w", name, err)
		}

		_, err = outFile.Write([]byte{i})
		if err != nil {
			return fmt.Errorf("error writing tag to output file '%s': %w", name, err)
		}
		_, err = outFile.Write(share)
		if err != nil {
			return fmt.Errorf("error writing share to output file '%s': %w", name, err)
		}

		outFile.Close()
	}

	return nil
}

func combine(args []string) error {
	// if either poly or gen is set, attempt to parse both.
	field := shamir.GaloisField
	if fs.ParsedArgs["poly"] != "" || fs.ParsedArgs["gen"] != "" {
		poly, err := strconv.ParseInt(fs.ParsedArgs["poly"], 0, 64)
		if err != nil {
			return fmt.Errorf("error parsing polynomial: %w", err)
		}
		gen, err := strconv.ParseInt(fs.ParsedArgs["gen"], 0, 64)
		if err != nil {
			return fmt.Errorf("error parsing generator: %w", err)
		}
		field = galois.New256(uint16(poly), byte(gen))
	}

	var output io.Writer
	outputFile := fs.ParsedArgs["output"]
	switch outputFile {
	// the output flag is empty/-/1/stdio/stdout: use stdout
	case "", "-", "1", "std", "stdio", "stdout":
		output = os.Stdout
	// the input flag is a file name: open the file
	default:
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("error opening output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	secrets := map[byte][]byte{}
	for _, fileName := range args {
		data, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("error opening share file: %w", err)
		}

		x, share := data[0], data[1:]
		secrets[x] = share
	}

	var combined []byte
	if fs.ParsedArgs["tagged"] == "" {
		combined = shamir.CombineWithField(field, secrets)
	} else {
		var err error
		combined, err = shamir.CombineTaggedWithField(field, secrets)
		if err != nil {
			return fmt.Errorf("error combining secrets, tag mismatch: %w", err)
		}
	}

	_, err := output.Write(combined)
	if err != nil {
		return fmt.Errorf("error writing output: %w", err)
	}
	return nil
}
