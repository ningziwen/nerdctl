/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nerdctl/pkg/testutil"
	"github.com/containerd/nerdctl/pkg/testutil/testregistry"
	"gotest.tools/v3/assert"
)

type cosignKeyPair struct {
	publicKey  string
	privateKey string
	cleanup    func()
}

func newCosignKeyPair(t testing.TB, path string) *cosignKeyPair {
	td, err := os.MkdirTemp(t.TempDir(), path)
	assert.NilError(t, err)

	cmd := exec.Command("cosign", "generate-key-pair")
	cmd.Dir = td
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to run %v: %v (%q)", cmd.Args, err, string(out))
	}

	publicKey := filepath.Join(td, "cosign.pub")
	privateKey := filepath.Join(td, "cosign.key")

	return &cosignKeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
		cleanup: func() {
			_ = os.RemoveAll(td)
		},
	}
}

func newNotationKeyPair(keyName string) error {
	cmd := exec.Command("notation", "cert", "generate-test", keyName)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func newNotationTrustPolicy(path string, certName string) error {
	b := []byte(fmt.Sprintf(`{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "e2e",
            "registryScopes": [ "*" ],
            "signatureVerification": {
                "level" : "strict"
            },
            "trustStores": [ "ca:%s" ],
            "trustedIdentities": [
                "*"
            ]
        }
    ]
}`, certName))
	err := os.WriteFile(fmt.Sprintf("%s/trustpolicy.json", path), b, 0644)
	if err != nil {
		return err
	}
	return nil
}

func TestImageVerifyWithCosign(t *testing.T) {
	testutil.RequireExecutable(t, "cosign")
	testutil.DockerIncompatible(t)
	testutil.RequiresBuild(t)
	t.Setenv("COSIGN_PASSWORD", "1")
	keyPair := newCosignKeyPair(t, "cosign-key-pair")
	defer keyPair.cleanup()
	base := testutil.NewBase(t)
	defer base.Cmd("builder", "prune").Run()
	tID := testutil.Identifier(t)
	reg := testregistry.NewPlainHTTP(base, 5000)
	defer reg.Cleanup()
	localhostIP := "127.0.0.1"
	t.Logf("localhost IP=%q", localhostIP)
	testImageRef := fmt.Sprintf("%s:%d/%s",
		localhostIP, reg.ListenPort, tID)
	t.Logf("testImageRef=%q", testImageRef)

	dockerfile := fmt.Sprintf(`FROM %s
CMD ["echo", "nerdctl-build-test-string"]
	`, testutil.CommonImage)

	buildCtx, err := createBuildContext(dockerfile)
	assert.NilError(t, err)
	defer os.RemoveAll(buildCtx)

	base.Cmd("build", "-t", testImageRef, buildCtx).AssertOK()
	base.Cmd("push", testImageRef, "--sign=cosign", "--cosign-key="+keyPair.privateKey).AssertOK()
	base.Cmd("pull", testImageRef, "--verify=cosign", "--cosign-key="+keyPair.publicKey).AssertOK()
}

func TestImagePullPlainHttpWithDefaultPort(t *testing.T) {
	testutil.DockerIncompatible(t)
	testutil.RequiresBuild(t)
	base := testutil.NewBase(t)
	defer base.Cmd("builder", "prune").Run()
	reg := testregistry.NewPlainHTTP(base, 80)
	defer reg.Cleanup()
	testImageRef := fmt.Sprintf("%s/%s:%s",
		reg.IP.String(), testutil.Identifier(t), strings.Split(testutil.CommonImage, ":")[1])
	t.Logf("testImageRef=%q", testImageRef)
	t.Logf("testImageRef=%q", testImageRef)
	dockerfile := fmt.Sprintf(`FROM %s
CMD ["echo", "nerdctl-build-test-string"]
	`, testutil.CommonImage)

	buildCtx, err := createBuildContext(dockerfile)
	assert.NilError(t, err)
	defer os.RemoveAll(buildCtx)
	base.Cmd("build", "-t", testImageRef, buildCtx).AssertOK()
	base.Cmd("--insecure-registry", "push", testImageRef).AssertOK()
	base.Cmd("--insecure-registry", "pull", testImageRef).AssertOK()
}

func TestImageVerifyWithCosignShouldFailWhenKeyIsNotCorrect(t *testing.T) {
	testutil.RequireExecutable(t, "cosign")
	testutil.DockerIncompatible(t)
	testutil.RequiresBuild(t)
	t.Setenv("COSIGN_PASSWORD", "1")
	keyPair := newCosignKeyPair(t, "cosign-key-pair")
	defer keyPair.cleanup()
	base := testutil.NewBase(t)
	defer base.Cmd("builder", "prune").Run()
	tID := testutil.Identifier(t)
	reg := testregistry.NewPlainHTTP(base, 5000)
	defer reg.Cleanup()
	localhostIP := "127.0.0.1"
	t.Logf("localhost IP=%q", localhostIP)
	testImageRef := fmt.Sprintf("%s:%d/%s",
		localhostIP, reg.ListenPort, tID)
	t.Logf("testImageRef=%q", testImageRef)

	dockerfile := fmt.Sprintf(`FROM %s
CMD ["echo", "nerdctl-build-test-string"]
	`, testutil.CommonImage)

	buildCtx, err := createBuildContext(dockerfile)
	assert.NilError(t, err)
	defer os.RemoveAll(buildCtx)

	base.Cmd("build", "-t", testImageRef, buildCtx).AssertOK()
	base.Cmd("push", testImageRef, "--sign=cosign", "--cosign-key="+keyPair.privateKey).AssertOK()
	base.Cmd("pull", testImageRef, "--verify=cosign", "--cosign-key="+keyPair.publicKey).AssertOK()

	t.Setenv("COSIGN_PASSWORD", "2")
	newKeyPair := newCosignKeyPair(t, "cosign-key-pair-test")
	base.Cmd("pull", testImageRef, "--verify=cosign", "--cosign-key="+newKeyPair.publicKey).AssertFail()
}

func TestImageVerifyWithNotation(t *testing.T) {
	testutil.RequireExecutable(t, "notation")
	testutil.DockerIncompatible(t)
	testutil.RequiresBuild(t)
	notationXDGConfigHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", notationXDGConfigHome)
	const keyName = "e2e-notation"
	err := newNotationKeyPair(keyName)
	if err != nil {
		t.Fatal(err)
	}
	trustPolicyPath := fmt.Sprintf("%s/.config/notation", notationXDGConfigHome)
	newNotationTrustPolicy(trustPolicyPath, keyName)
	defer os.RemoveAll(notationXDGConfigHome)
	base := testutil.NewBase(t)
	defer base.Cmd("builder", "prune").Run()
	tID := testutil.Identifier(t)
	reg := testregistry.NewPlainHTTP(base, 5000)
	defer reg.Cleanup()
	localhostIP := "127.0.0.1"
	t.Logf("localhost IP=%q", localhostIP)
	testImageRef := fmt.Sprintf("%s:%d/%s",
		localhostIP, reg.ListenPort, tID)
	t.Logf("testImageRef=%q", testImageRef)

	dockerfile := fmt.Sprintf(`FROM %s
CMD ["echo", "nerdctl-build-test-string"]
	`, testutil.CommonImage)

	buildCtx, err := createBuildContext(dockerfile)
	assert.NilError(t, err)
	defer os.RemoveAll(buildCtx)

	base.Cmd("build", "-t", testImageRef, buildCtx).AssertOK()
	base.Cmd("push", testImageRef, "--sign=notation", "--notation-key-name="+keyName).AssertOK()
	base.Cmd("pull", testImageRef, "--verify=notation").AssertFail()
}

func TestImageVerifyWithNotationShouldFailWhenKeyIsNotCorrect(t *testing.T) {
	testutil.RequireExecutable(t, "notation")
	testutil.DockerIncompatible(t)
	testutil.RequiresBuild(t)
	notationXDGConfigHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", notationXDGConfigHome)
	const keyName = "e2e-notation"
	err := newNotationKeyPair(keyName)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(notationXDGConfigHome)
	base := testutil.NewBase(t)
	defer base.Cmd("builder", "prune").Run()
	tID := testutil.Identifier(t)
	reg := testregistry.NewPlainHTTP(base, 5000)
	defer reg.Cleanup()
	localhostIP := "127.0.0.1"
	t.Logf("localhost IP=%q", localhostIP)
	testImageRef := fmt.Sprintf("%s:%d/%s",
		localhostIP, reg.ListenPort, tID)
	t.Logf("testImageRef=%q", testImageRef)

	dockerfile := fmt.Sprintf(`FROM %s
CMD ["echo", "nerdctl-build-test-string"]
	`, testutil.CommonImage)

	buildCtx, err := createBuildContext(dockerfile)
	assert.NilError(t, err)
	defer os.RemoveAll(buildCtx)

	base.Cmd("build", "-t", testImageRef, buildCtx).AssertOK()
	base.Cmd("push", testImageRef, "--sign=notation", "--notation-key-name="+keyName).AssertOK()
	base.Cmd("pull", testImageRef, "--verify=notation").AssertFail()
}
