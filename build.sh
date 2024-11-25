#!/bin/bash
if [ -z "$BASH_VERSION" ]
then
	echo "This script must be run in BASH."
	exit 1
fi

# Bail on any failure
set -e

# Check for required commands
command -v go >/dev/null
command -v tar >/dev/null
command -v base64 >/dev/null
command -v sha256sum >/dev/null

# Vars
repoRoot=$(pwd)
serverSRCdir="server"
clientSRCdir="client"

function usage {
	echo "Usage $0

Options:
  -a <arch>   Architecture of compiled binary (amd64, arm64) [default: amd64]
  -b <prog>   Which program to build (client, server)
  -o <os>     Which operating system to build for (linux, windows) [default: linux]
  -f          Build nicely named binary
"
}

function client_binary {
	# Move into dir
	cd $clientSRCdir

	# Vars for build
	inputGoSource="*.go"
	outputEXE="secureknock"
	export CGO_ENABLED=0
	export GOARCH=$1
	export GOOS=$2

	# Build binary
	go build -o $repoRoot/$outputEXE -a -ldflags '-s -w -buildid= -extldflags "-static"' $inputGoSource
	cd $repoRoot

	# Rename to more descriptive if full build was requested
	if [[ $3 == true ]]
	then
		# Get version
		version=$(./$outputEXE -v)
		clientEXE=""$outputEXE"_"$version"_$GOOS-$GOARCH-static"

		# Rename with version
		mv $outputEXE $clientEXE
		sha256sum $clientEXE > "$clientEXE".sha256
	fi
}

function server_package {
	# Move into dir
	cd $repoRoot/$serverSRCdir

	# Vars for build
	outputEXE="secureknockd"
	unset CGO_ENABLED
	export GOARCH=$1
	export GOOS=$2

	# Build binary
	go build -o $repoRoot/$outputEXE -a -ldflags '-s -w -buildid=' *.go
	cd $repoRoot
	
	# Create install script
	tar -cvzf $outputEXE.tar.gz $outputEXE
	cp $repoRoot/$serverSRCdir/install-secureknock-server.sh "$outputEXE"_install.sh
	cat $outputEXE.tar.gz | base64 >> "$outputEXE"_install.sh

	# Rename to more descriptive if full build was requested
	if [[ $3 == true ]]
	then
		# Get version
		version=$(./$outputEXE -v)
		serverPKG=""$outputEXE"_"$version"_$GOOS-$GOARCH-static"

		# Rename with version
		mv $outputEXE_install.sh $serverPKG
		sha256sum $serverPKG > "$serverPKG".sha256
	fi

	# Cleanup
	rm $outputEXE.tar.gz $outputEXE
}

function server_binary {
	# Move into dir
	cd $repoRoot/$serverSRCdir

	# Vars for build
	inputGoSource="*.go"
	outputEXE="secureknockd"
	unset CGO_ENABLED
	export GOARCH=$1
	export GOOS=$2

	# Build binary
	go build -o $repoRoot/$outputEXE -a -ldflags '-s -w -buildid=' $inputGoSource
	cd $repoRoot

	# Make nicely named binary if requested
	if [[ $3 == true ]]
	then
		# Get version
		version=$(./$outputEXE -v)
		serverEXE=""$outputEXE"_"$version"_$GOOS-$GOARCH-dynamic"

		# Rename with version
		mv $outputEXE $serverEXE
		sha256sum $serverEXE > "$serverEXE".sha256
	fi
}

## START
# DEFAULT CHOICES
buildfull='false'
architecture="amd64"
os="linux"

# Argument parsing
while getopts 'a:b:o:fh' opt
do
	case "$opt" in
	  'a')
	    architecture="$OPTARG"
	    ;;
	  'b')
	    buildopt="$OPTARG"
	    ;;
	  'f')
	    buildfull='true'
	    ;;
	  'o')
	    os="$OPTARG"
	    ;;
	  'h')
	    echo "Unknown Option"
	    usage
	    exit 0
 	    ;;
	esac
done

if [[ $buildopt == client ]]
then
	client_binary "$architecture" "$os" "$buildfull"
	echo "Complete: client binary built"
elif [[ $buildopt == serverpkg ]]
then
	server_package "$architecture" "$os" "$buildfull"
	echo "Complete: server package built"
elif [[ $buildopt == server ]]
then
	server_binary "$architecture" "$os" "$buildfull" "$nosig"
	echo "Complete: server binary built"
fi

exit 0
