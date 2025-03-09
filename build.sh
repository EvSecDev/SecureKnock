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
SRCdir="src"

function usage {
	echo "Usage $0

Options:
  -a <arch>   Architecture of compiled binary (amd64, arm64) [default: amd64]
  -b <prog>   Which program to build (exe, pkg)
  -o <os>     Which operating system to build for (linux, windows) [default: linux]
  -u          Update go packages for program
  -f          Build nicely named binary
"
}

function check_for_dev_artifacts {
    # function args
    SRCdir=$1

    # Quick check for any left over debug prints
    if grep -ER "DEBUG" $SRCdir/*.go
    then
        echo "  [-] Debug print found in source code. You might want to remove that before release."
    fi

    # Quick staticcheck check - ignoring punctuation in error strings
    cd $SRCdir
    set +e
    staticcheck *.go | egrep -v "error strings should not"
    set -e
    cd $repoRoot/
}

function build {
	# Always ensure we start in the root of the repository
    cd $repoRoot/

    # Check for things not supposed to be in a release
    check_for_dev_artifacts "$SRCdir"

	# Move into dir
	cd ${repoRoot}/${SRCdir}

    # Run tests
    go test

	# Vars for build
	inputGoSource="*.go"
	outputEXE="secureknock"
	unset CGO_ENABLED
	export GOARCH=$1
	export GOOS=$2

	# Build binary
	go build -o ${repoRoot}/${outputEXE} -a -ldflags '-s -w -buildid=' $inputGoSource
	cd $repoRoot

	# Get version and set name if nice naming requested
	if [[ $3 == true ]]
	then
	        # Get version
                version=$(./$outputEXE --versionid)
                serverEXE="${outputEXE}_${version}_${GOOS}-${GOARCH}-dynamic"
	fi

	# Build install package
	if [[ $4 == true ]]
	then
	        tar -cvzf ${outputEXE}.tar.gz ${outputEXE}
        	cp ${repoRoot}/${SRCdir}/install-secureknock-server.sh ${outputEXE}_install.sh
	        cat ${outputEXE}.tar.gz | base64 >> ${outputEXE}_install.sh
		rm ${outputEXE}.tar.gz
	fi

	# Make nicely named binary if requested
	if [[ $3 == true ]]
	then
		if [[ -f ${outputEXE}_install.sh ]]
		then
			# For package naming
			mv ${outputEXE}_install.sh ${serverEXE}_installer.sh
			sha256sum ${serverEXE}_installer.sh > ${serverEXE}_installer.sh.sha256
		else
			# For single binary
			mv $outputEXE $serverEXE
			sha256sum $serverEXE > ${serverEXE}.sha256
		fi
	fi
}

function update_go_packages {
        # Always ensure we start in the root of the repository
        cd $repoRoot/

        # Move into src dir
        cd $SRCdir

        # Run go updates
        echo "==== Updating Go packages ===="
        go get -u all
        go mod verify
        go mod tidy
        echo "==== Updates Finished ===="
}

## START
# DEFAULT CHOICES
buildfull='false'
architecture="amd64"
os="linux"
buildpackage='false'

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
        'u')
        updatepackages='true'
        ;;
	  'h')
	    usage
	    exit 0
 	    ;;
          *)
            usage
            exit 0
            ;;
	esac
done

if [[ $buildopt == pkg ]]
then
	buildpackage='true'
fi

if [[ $updatepackages == true ]]
then
    # Using the builtopt cd into the src dir and update packages then exit
    update_go_packages
    exit 0
elif [[ $buildopt == exe ]]
then
	build "$architecture" "$os" "$buildfull" "$buildpackage"
	echo "Complete: binary built"
fi

exit 0
