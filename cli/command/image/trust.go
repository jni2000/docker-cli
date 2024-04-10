package image

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
        "net"
        "time"
        "os"
        "os/exec"
        "bufio"
        "log"
        "strings"

	"github.com/distribution/reference"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/streams"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/registry"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/tuf/data"
)

type target struct {
	name   string
	digest digest.Digest
	size   int64
}

// CommScope signed signing log
type CommScopeSigningLog struct {
        Title string
        IpAddr []string 
        MacAddr []string
        TimeStamp string
        NotaryKeyId string
        NotarySignature string
        Subject string
        CsKeyId string
        CsCaId  string
        Signature string
}

type CommScopeSignature struct {
	KeyId string
	Algorithm string
	Signature []byte
	Flag	bool
}

type CommScopeKeyId struct {
	KeyIds []string
	Count int8
}

type CommScopeRoleInfo struct {
	KeyIdInfo CommScopeKeyId
	KeyName string
	Misc []string
}

type CommScopeRole struct {
	SignarureInfo []CommScopeSignature
	RoleInfo CommScopeRoleInfo	
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func getMacAddr() ([]string, error) {
     ifas, err := net.Interfaces()
     if err != nil {
         return nil, err
     }
     var as []string
     for _, ifa := range ifas {
         a := ifa.HardwareAddr.String()
         if a != "" {
             as = append(as, a)
         }
     }
     return as, nil
}


// TrustedPush handles content trust pushing of an image
func TrustedPush(ctx context.Context, cli command.Cli, repoInfo *registry.RepositoryInfo, ref reference.Named, authConfig registrytypes.AuthConfig, options image.PushOptions) error {
	responseBody, err := cli.Client().ImagePush(ctx, reference.FamiliarString(ref), options)
	if err != nil {
		return err
	}

	defer responseBody.Close()

	return PushTrustedReference(cli, repoInfo, ref, authConfig, responseBody)
}

// PushTrustedReference pushes a canonical reference to the trust server.
//
//nolint:gocyclo
func PushTrustedReference(ioStreams command.Streams, repoInfo *registry.RepositoryInfo, ref reference.Named, authConfig registrytypes.AuthConfig, in io.Reader) error {
	// If it is a trusted push we would like to find the target entry which match the
	// tag provided in the function and then do an AddTarget later.
	target := &client.Target{}
	// Count the times of calling for handleTarget,
	// if it is called more that once, that should be considered an error in a trusted push.
	cnt := 0
	var digest_value string

	handleTarget := func(msg jsonmessage.JSONMessage) {
		cnt++
		if cnt > 1 {
			// handleTarget should only be called once. This will be treated as an error.
			return
		}

		var pushResult types.PushResult
		err := json.Unmarshal(*msg.Aux, &pushResult)
		if err == nil && pushResult.Tag != "" {
			if dgst, err := digest.Parse(pushResult.Digest); err == nil {
				h, err := hex.DecodeString(dgst.Hex())
				if err != nil {
					target = nil
					return
				}
				digest_value = dgst.Hex()
				target.Name = pushResult.Tag
				target.Hashes = data.Hashes{string(dgst.Algorithm()): h}
				target.Length = int64(pushResult.Size)
			}
		}
	}

	var tag string
	switch x := ref.(type) {
	case reference.Canonical:
		return errors.New("cannot push a digest reference")
	case reference.NamedTagged:
		tag = x.Tag()
	default:
		// We want trust signatures to always take an explicit tag,
		// otherwise it will act as an untrusted push.
		if err := jsonmessage.DisplayJSONMessagesToStream(in, ioStreams.Out(), nil); err != nil {
			return err
		}
		fmt.Fprintln(ioStreams.Err(), "No tag specified, skipping trust metadata push")
		return nil
	}

	if err := jsonmessage.DisplayJSONMessagesToStream(in, ioStreams.Out(), handleTarget); err != nil {
		return err
	}

	if cnt > 1 {
		return errors.Errorf("internal error: only one call to handleTarget expected")
	}

	if target == nil {
		return errors.Errorf("no targets found, please provide a specific tag in order to sign it")
	}

	fmt.Fprintln(ioStreams.Out(), "Signing and pushing trust metadata")

	repo, err := trust.GetNotaryRepository(ioStreams.In(), ioStreams.Out(), command.UserAgent(), repoInfo, &authConfig, "push", "pull")

	if err != nil {
		return errors.Wrap(err, "error establishing connection to trust repository")
	}

	// get the latest repository metadata so we can figure out which roles to sign
	_, err = repo.ListTargets()

	switch err.(type) {
	case client.ErrRepoNotInitialized, client.ErrRepositoryNotExist:
		keys := repo.GetCryptoService().ListKeys(data.CanonicalRootRole)
		var rootKeyID string
		// always select the first root key
		if len(keys) > 0 {
			sort.Strings(keys)
			rootKeyID = keys[0]
		} else {
			rootPublicKey, err := repo.GetCryptoService().Create(data.CanonicalRootRole, "", data.ECDSAKey)
			if err != nil {
				return err
			}
			rootKeyID = rootPublicKey.ID()
		}

		// Initialize the notary repository with a remotely managed snapshot key
		if err := repo.Initialize([]string{rootKeyID}, data.CanonicalSnapshotRole); err != nil {
			return trust.NotaryError(repoInfo.Name.Name(), err)
		}
		fmt.Fprintf(ioStreams.Out(), "Finished initializing %q\n", repoInfo.Name.Name())
		err = repo.AddTarget(target, data.CanonicalTargetsRole)
	case nil:
		// already initialized and we have successfully downloaded the latest metadata
		err = AddTargetToAllSignableRoles(repo, target)
	default:
		return trust.NotaryError(repoInfo.Name.Name(), err)
	}

	if err == nil {
		err = repo.Publish()
	}

	if err != nil {
		err = errors.Wrapf(err, "failed to sign %s:%s", repoInfo.Name.Name(), tag)
		return trust.NotaryError(repoInfo.Name.Name(), err)
	}

	// targs, _ := repo.ListTargets()
	// for _, targ := range targs { 
	//	fmt.Println("Targets: ", *targ)
	// }

	roles, _ := repo.ListRoles()
	for _, role := range roles {
		roleJson := fmt.Sprintf("Role: %s", role)
		fmt.Println(roleJson)
	}

        // invoking CommScope PRiSM RESTful API call to sign 
       	// target.Name, target.Hashes 
	signRec := CommScopeSigningLog{Title: "CommScope target signature attestation record"}

        fmt.Println("invoking CommScope PKI signning service.....")
        signRec.Subject = repoInfo.Name.Name() + ":" + target.Name
        signRec.NotarySignature = digest_value
        signRec.CsKeyId = "PRiSMRESTClient_COMM.GEN.PKICTest.210910.1"
        signRec.CsCaId ="ArrisPKICenterRootandSubCA"
	payload1 := `{"clientSystemID":"testsystemID","clientUserID":"COMM.GEN.PKICTest.210910.1","clientSite":"test site","configPath":"/ARRIS/Demonstration/Demonstration/PKCS1","hashAlgo":"sha256","hash":"`
        payload2 := digest_value
        payload3 := `"}`
        payload := payload1+payload2+payload3

	cmd := exec.Command("curl", "-X", "POST", "--cert-type", "P12", "--cert", "~/workspace/notary/PRiSM/PRiSMRESTClient_COMM.GEN.PKICTest.210910.1-2.pfx", "--cacert", "~/workspace/notary/PRiSM/ArrisPKICenterRootandSubCA.cer", "-H", "Content-Type: application/json", "-d", payload, "https://usacasd-prism-test.arrisi.com:4443/api/v1/signatureoverhash")
        stdout, _ := cmd.StdoutPipe()
        scanner := bufio.NewScanner(stdout)
        done := make(chan bool)
        cmd_ret := ""
        go func() {
            for scanner.Scan() {
                cmd_ret = scanner.Text()
            }
            done <- true
        }()
        cmd.Start()
        <- done
        err = cmd.Wait()
        signRec.Signature = strings.Replace(cmd_ret, "\"", "", -1)

         // signing log
        addrs, err1 := net.InterfaceAddrs()
        if err1 != nil {
            panic(err1)
        }
        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
                signRec.IpAddr = append(signRec.IpAddr, ipNet.IP.String())
            }
        }
        as, err2 := getMacAddr()
        if err2 != nil {
            log.Fatal(err2)
        }
        for _, a := range as {
            signRec.MacAddr = append(signRec.MacAddr, string(a))
        }
        currentTime := time.Now()
        signRec.TimeStamp = currentTime.String()
        // signRec.NotaryKeyId = rootKeyID
        signJson, err3 := json.Marshal(&signRec)
        if err3 != nil {
            log.Fatal(err3)
        }
        signString := string(signJson)
        fmt.Println("singRec is:", signString)
        filename := "/tmp/" + "test.log"
        fmt.Println("write to file: ", filename)
        err = os.WriteFile(filename, []byte(signString), 0644)
        check(err)

	fmt.Fprintf(ioStreams.Out(), "Successfully signed %s:%s\n", repoInfo.Name.Name(), tag)
	return nil
}

// AddTargetToAllSignableRoles attempts to add the image target to all the top level delegation roles we can
// (based on whether we have the signing key and whether the role's path allows
// us to).
// If there are no delegation roles, we add to the targets role.
func AddTargetToAllSignableRoles(repo client.Repository, target *client.Target) error {
	signableRoles, err := trust.GetSignableRoles(repo, target)
	if err != nil {
		return err
	}

	return repo.AddTarget(target, signableRoles...)
}

// trustedPull handles content trust pulling of an image
func trustedPull(ctx context.Context, cli command.Cli, imgRefAndAuth trust.ImageRefAndAuth, opts PullOptions) error {
	refs, err := getTrustedPullTargets(cli, imgRefAndAuth)
	if err != nil {
		return err
	}

	ref := imgRefAndAuth.Reference()
	for i, r := range refs {
		displayTag := r.name
		if displayTag != "" {
			displayTag = ":" + displayTag
		}
		fmt.Fprintf(cli.Out(), "Pull (%d of %d): %s%s@%s\n", i+1, len(refs), reference.FamiliarName(ref), displayTag, r.digest)

		trustedRef, err := reference.WithDigest(reference.TrimNamed(ref), r.digest)
		if err != nil {
			return err
		}
		updatedImgRefAndAuth, err := trust.GetImageReferencesAndAuth(ctx, AuthResolver(cli), trustedRef.String())
		if err != nil {
			return err
		}
		if err := imagePullPrivileged(ctx, cli, updatedImgRefAndAuth, PullOptions{
			all:      false,
			platform: opts.platform,
			quiet:    opts.quiet,
			remote:   opts.remote,
		}); err != nil {
			return err
		}

		tagged, err := reference.WithTag(reference.TrimNamed(ref), r.name)
		if err != nil {
			return err
		}

		if err := TagTrusted(ctx, cli, trustedRef, tagged); err != nil {
			return err
		}
	}
	return nil
}

func getTrustedPullTargets(cli command.Cli, imgRefAndAuth trust.ImageRefAndAuth) ([]target, error) {
	notaryRepo, err := cli.NotaryClient(imgRefAndAuth, trust.ActionsPullOnly)
	if err != nil {
		return nil, errors.Wrap(err, "error establishing connection to trust repository")
	}

	ref := imgRefAndAuth.Reference()
	tagged, isTagged := ref.(reference.NamedTagged)
	if !isTagged {
		// List all targets
		targets, err := notaryRepo.ListTargets(trust.ReleasesRole, data.CanonicalTargetsRole)
		if err != nil {
			return nil, trust.NotaryError(ref.Name(), err)
		}
		var refs []target
		for _, tgt := range targets {
			t, err := convertTarget(tgt.Target)
			if err != nil {
				fmt.Fprintf(cli.Err(), "Skipping target for %q\n", reference.FamiliarName(ref))
				continue
			}
			// Only list tags in the top level targets role or the releases delegation role - ignore
			// all other delegation roles
			if tgt.Role != trust.ReleasesRole && tgt.Role != data.CanonicalTargetsRole {
				continue
			}
			refs = append(refs, t)
		}
		if len(refs) == 0 {
			return nil, trust.NotaryError(ref.Name(), errors.Errorf("No trusted tags for %s", ref.Name()))
		}
		return refs, nil
	}

	t, err := notaryRepo.GetTargetByName(tagged.Tag(), trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, trust.NotaryError(ref.Name(), err)
	}
	// Only get the tag if it's in the top level targets role or the releases delegation role
	// ignore it if it's in any other delegation roles
	if t.Role != trust.ReleasesRole && t.Role != data.CanonicalTargetsRole {
		return nil, trust.NotaryError(ref.Name(), errors.Errorf("No trust data for %s", tagged.Tag()))
	}

	logrus.Debugf("retrieving target for %s role", t.Role)
	r, err := convertTarget(t.Target)
	return []target{r}, err
}

// imagePullPrivileged pulls the image and displays it to the output
func imagePullPrivileged(ctx context.Context, cli command.Cli, imgRefAndAuth trust.ImageRefAndAuth, opts PullOptions) error {
	encodedAuth, err := registrytypes.EncodeAuthConfig(*imgRefAndAuth.AuthConfig())
	if err != nil {
		return err
	}
	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(cli, imgRefAndAuth.RepoInfo().Index, "pull")
	responseBody, err := cli.Client().ImagePull(ctx, reference.FamiliarString(imgRefAndAuth.Reference()), image.PullOptions{
		RegistryAuth:  encodedAuth,
		PrivilegeFunc: requestPrivilege,
		All:           opts.all,
		Platform:      opts.platform,
	})
	if err != nil {
		return err
	}
	defer responseBody.Close()

	out := cli.Out()
	if opts.quiet {
		out = streams.NewOut(io.Discard)
	}
	return jsonmessage.DisplayJSONMessagesToStream(responseBody, out, nil)
}

// TrustedReference returns the canonical trusted reference for an image reference
func TrustedReference(ctx context.Context, cli command.Cli, ref reference.NamedTagged) (reference.Canonical, error) {
	imgRefAndAuth, err := trust.GetImageReferencesAndAuth(ctx, AuthResolver(cli), ref.String())
	if err != nil {
		return nil, err
	}

	notaryRepo, err := cli.NotaryClient(imgRefAndAuth, []string{"pull"})
	if err != nil {
		return nil, errors.Wrap(err, "error establishing connection to trust repository")
	}

	t, err := notaryRepo.GetTargetByName(ref.Tag(), trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, trust.NotaryError(imgRefAndAuth.RepoInfo().Name.Name(), err)
	}
	// Only list tags in the top level targets role or the releases delegation role - ignore
	// all other delegation roles
	if t.Role != trust.ReleasesRole && t.Role != data.CanonicalTargetsRole {
		return nil, trust.NotaryError(imgRefAndAuth.RepoInfo().Name.Name(), client.ErrNoSuchTarget(ref.Tag()))
	}
	r, err := convertTarget(t.Target)
	if err != nil {
		return nil, err
	}
	return reference.WithDigest(reference.TrimNamed(ref), r.digest)
}

func convertTarget(t client.Target) (target, error) {
	h, ok := t.Hashes["sha256"]
	if !ok {
		return target{}, errors.New("no valid hash, expecting sha256")
	}
	return target{
		name:   t.Name,
		digest: digest.NewDigestFromHex("sha256", hex.EncodeToString(h)),
		size:   t.Length,
	}, nil
}

// TagTrusted tags a trusted ref
func TagTrusted(ctx context.Context, cli command.Cli, trustedRef reference.Canonical, ref reference.NamedTagged) error {
	// Use familiar references when interacting with client and output
	familiarRef := reference.FamiliarString(ref)
	trustedFamiliarRef := reference.FamiliarString(trustedRef)

	fmt.Fprintf(cli.Err(), "Tagging %s as %s\n", trustedFamiliarRef, familiarRef)

	return cli.Client().ImageTag(ctx, trustedFamiliarRef, familiarRef)
}

// AuthResolver returns an auth resolver function from a command.Cli
func AuthResolver(cli command.Cli) func(ctx context.Context, index *registrytypes.IndexInfo) registrytypes.AuthConfig {
	return func(ctx context.Context, index *registrytypes.IndexInfo) registrytypes.AuthConfig {
		return command.ResolveAuthConfig(cli.ConfigFile(), index)
	}
}
