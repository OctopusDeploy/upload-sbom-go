# Upload SBOM Go

## Input Variables
| Flag      | Env Var               | Description                                             |
|-----------|-----------------------|---------------------------------------------------------|
| --url     | SBOM_UPLOADER_URL     | Dependency-Track API base URL                           |
| --api-key | SBOM_UPLOADER_API_KEY | Dependency-Track API key                                |
| --name    | SBOM_UPLOADER_NAME    | Project name for Dependency Track                       |
| --version | SBOM_UPLOADER_VERSION | Project version for Dependency Track                    |
| --parent  | SBOM_UPLOADER_PARENT  | Parent project for Dependency Track                     |
| --tags    | SBOM_UPLOADER_TAGS    | Comma-separated project tags                            |
| --latest  |                       | Mark as latest version (default true)                   |
| --sbom    |                       | Path to SBOM file (optional; otherwise read from stdin) |

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
      --api-key string   Dependency-Track API key or env SBOM_UPLOADER_API_KEY
  -h, --help             help for sbom-uploader
      --latest           Mark as latest version (default true) (default true)
      --name string      Project name or env SBOM_UPLOADER_NAME
      --parent string    Parent project name or env SBOM_UPLOADER_PARENT
      --sbom string      Path to SBOM file (optional; otherwise read from stdin)
      --tags string      Comma-separated project tags or env SBOM_UPLOADER_TAGS
      --url string       Dependency-Track API base URL or env SBOM_UPLOADER_URL
      --version string   Project version or env SBOM_UPLOADER_VERSION
```

### Docker Volume Mount
When using Docker the SBOM file should be mounted as a volume mount.

```
ls bom.json # Sbom file locally on filesystem
docker run --rm -it -e SBOM_UPLOADER_API_KEY="SBOM_UPLOADER_API_KEY" -v $(pwd):/tmp upload-sbom --url "https://dependencytrack-api.local" --version "0.0.1" --tags "tag1,tag2" --parent "parentname" --name "projectname" --latest --sbom /tmp/bom.json
```

### Docker ENV Vars
Env vars can be stored in a file and passed in using the `env-file` argument.

Env File `.env`:
```
SBOM_UPLOADER_URL=https://dependencytrack-api.local
SBOM_UPLOADER_API_KEY=FOOBAR
SBOM_UPLOADER_NAME=projectname
SBOM_UPLOADER_VERSION=0.0.1
SBOM_UPLOADER_PARENT=parentname
SBOM_UPLOADER_TAGS=tag1,tag2
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

## Dependency Track API Key
When creating a Dependency Track API key the permissions required are as follows:
- PROJECT_CREATION_UPLOAD
  - _Required for creating the project._
- BOM_UPLOAD
  - _Required for uploading the SBOM._

## Common Errors
### HTTP 403 upload failed
If you encounter an HTTP `403` error this means your API key does not have the appropriate access. See (Dependency Track API Key) above.
```
Execution failed: upload failed (403): 
Error: Process completed with exit code 1.
```

### HTTP 404 upload failed
If your action runs into an HTTP `404` error it is because the parent project does not exist. You must manually create a parent project in Dependency Track first.
```
Error: upload failed (404): The parent component could not be found.
```