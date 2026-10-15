# maisecrets-ci

This repository is CI only. It is not an install source.

The GitLab merge request pipeline of maisecrets pushes the commit of a merge request to a branch
`ci-mr/<iid>-<sha12>` here. The GitHub Actions workflow of that commit (`.github/workflows/ci.yml`)
runs the tests on Windows and macOS. The pipeline deletes old branches.

The plugin, its issues and its releases are at https://github.com/Mcpgate-de/maisecrets.
