# Upload SBOM Go

## Input Variables
| Flag      | Env Var              | Description                                             |
|-----------|----------------------|---------------------------------------------------------|
| --url     | DEPENDENCY_TRACK_URL | Dependency-Track API base URL                           |
| --api-key | DEPENDENCY_TRACK_KEY | Dependency-Track API key                                |
| --name    | PROJECT_NAME         | Project name for Dependency Track                       |
| --version | PROJECT_VERSION      | Project version for Dependency Track                    |
| --parent  | PROJECT_PARENT       | Parent project for Dependency Track                     |
| --tags    | PROJECT_TAGS         | Comma-separated project tags                            |
| --latest  |                      | Mark as latest version (default true)                   |
| --sbom    |                      | Path to SBOM file (optional; otherwise read from stdin) |

## Building
### Go
`go build .`

### Docker
`docker pull ghcr.io/octopusdeploy/sbom-uploader-go:latest`
or build
`docker build -t upload-sbom .`

## Usage
### CLI
```
./upload-sbom-go 
Usage:
  sbom-uploader [flags]

Flags:
      --api-key string   Dependency-Track API key or env DEPENDENCY_TRACK_KEY
  -h, --help             help for sbom-uploader
      --latest           Mark as latest version (default true) (default true)
      --name string      Project name or env PROJECT_NAME
      --parent string    Parent project name or env PROJECT_PARENT
      --sbom string      Path to SBOM file (optional; otherwise read from stdin)
      --tags string      Comma-separated project tags or env PROJECT_TAGS
      --url string       Dependency-Track API base URL or env DEPENDENCY_TRACK_URL
      --version string   Project version or env PROJECT_VERSION
```

### Docker Volume Mount
When using Docker the SBOM file should be mounted as a volume mount.

```
ls bom.json # Sbom file locally on filesystem
docker run --rm -it -e DEPENDENCY_TRACK_KEY="$DEPENDENCY_TRACK_KEY" -v $(pwd):/tmp upload-sbom --url "https://dependencytrack-api.local" --version "0.0.1" --tags "tag1,tag2" --parent "parentname" --name "projectname" --latest --sbom /tmp/bom.json
```

### Docker ENV Vars
Env vars can be stored in a file and passed in using the `env-file` argument.

Env File `.env`:
```
DEPENDENCY_TRACK_URL=https://dependencytrack-api.local
DEPENDENCY_TRACK_KEY=FOOBAR
PROJECT_NAME=projectname
PROJECT_VERSION=0.0.1
PROJECT_PARENT=parentname
PROJECT_TAGS=tag1,tag2
```

Running Docker:
```
docker run --rm -it --env-file=.env -v $(pwd):/tmp upload-sbom --sbom /tmp/bom.json
```

## GitHub Actions
Make sure to generate a SBOM file before using this step. The `is-latest` flag should be set to `true` or `false`, likely based on if the branch is `main`. 

Usage:
```
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM with Trivy
        uses: aquasecurity/trivy-action@0.32.0
        with:
          format: 'cyclonedx'
          scan-type: 'fs'
          scan-ref: '.'
          output: 'bom.json'

      - name: Upload SBOM to Dependency Track
        uses: OctopusDeploy/upload-sbom-go@v0.0.2
        with:
          dependency-track-url: ${{ secrets. }}
          dependency-track-key: ${{ secrets. }}
          project-name: my-project
          project-version: 0.0.0
          parent-name: my-parent
          is-latest: true
          project-tags: tag1,tag2
          sbom-file: "bom.json"
          github-actor: ${{ github.actor }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```