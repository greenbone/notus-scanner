// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package products

import (
	"fmt"
	"strings"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/nasl"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	"github.com/greenbone/ospd-openvas/smoketest/usecases"
)

func toTarget(uph string) (*scan.Target, error) {
	tl := strings.Split(uph, ":")
	if len(tl) != 2 {
		return nil, fmt.Errorf("%s is not in the pattern user:password@host.", uph)
	}
	user := tl[0]
	tl = strings.Split(tl[1], "@")
	if len(tl) != 2 {
		return nil, fmt.Errorf("%s is not in the pattern user:password@host.", uph)
	}
	pw := tl[0]
	host := tl[1]

	credential := scan.Credential{
		Type:     "up",
		Service:  "ssh",
		Username: user,
		Password: pw,
	}

	target := scan.Target{
		Hosts:            host,
		Ports:            "22",
		AliveTestMethods: scan.Alive,
		Credentials: scan.Credentials{
			Credentials: []scan.Credential{credential},
		},
	}
	return &target, nil
}

type GatherPackageListTests struct {
	NASLCache     *nasl.Cache
	PolicyCache   *policies.Cache
	Sender        connection.OSPDSender
	ProductLookup map[string]Product
}

func (gt *GatherPackageListTests) CreateCMD(uph string) (scan.Start, error) {
	ps := gt.PolicyCache.ByName("gatherpackagelist").AsVTSelection(gt.NASLCache)
	selection := scan.VTSelection{
		Single: make([]scan.VTSingle, 0),
		Group:  make([]scan.VTGroup, 0),
	}
	selection.Group = append(selection.Group, ps.Group...)
	selection.Single = append(selection.Single, ps.Single...)
	target, err := toTarget(uph)
	if err != nil {
		return scan.Start{}, err
	}
	return scan.Start{
		Targets:       scan.Targets{Targets: []scan.Target{*target}},
		VTSelection:   []scan.VTSelection{selection},
		ScannerParams: scan.DefaultScannerParams,
	}, nil

}

func (gplt *GatherPackageListTests) TestHost(ubh string) *usecases.Response {
	cmd, err := gplt.CreateCMD(ubh)
	if err != nil {
		return &usecases.Response{Success: false, Description: err.Error()}
	}
	var hn string
	if hf := strings.Split(ubh, "@"); len(hf) > 1 {
		hn = hf[1]
	}

	resp := usecases.StartScanGetLastStatus(cmd, gplt.Sender, PrintResponses{Host: hn})
	if resp.Failure != nil {
		return resp.Failure
	}
	var osname string
	vulnfindings := make(map[string][]PackageVulnerability)
	for _, r := range resp.Resp.Scan.Results.Results {
		// may hostname when gatherpackagelist testid
		if r.TestID == "1.3.6.1.4.1.25623.1.0.50282" && r.Name == "Determine OS and list of installed packages via SSH login" {
			osname = ParseOSName(r.Value)
		}
		// we assume notus result r.Port package
		if r.Port == "package" {
			vs := ParseVulnerabilityFindings(r.Value)
			if len(vs) > 0 {

				pvs, ok := vulnfindings[r.TestID]
				if !ok {
					pvs = vs
				} else {
					pvs = append(pvs, vs...)
				}
				vulnfindings[r.TestID] = pvs
			}

		}
	}
	prd, ok := gplt.ProductLookup[osname]
	if !ok {
		return &usecases.Response{Description: fmt.Sprintf("No product for %s found", osname)}
	}

	if len(vulnfindings) == 0 {
		return &usecases.Response{Description: fmt.Sprintf("No vulnerabilities found for %s found", osname)}
	}

	for k, v := range vulnfindings {
		adv := prd.FindAdvisoryByOID(k)
		if adv == nil {
			return &usecases.Response{Description: fmt.Sprintf("No advisory %s found in product %s", k, osname)}
		}
		for _, vu := range v {
			if adv.Find(vu.Fixed) == nil {
				return &usecases.Response{Description: fmt.Sprintf("No fixed version (%s) found in advisory %s within product %s", vu.Fixed, k, osname)}
			}
		}
	}

	return &usecases.Response{Success: true}
}

type PrintResponses struct {
	Host string
}

func (pr PrintResponses) Each(r scan.GetScansResponse) {
	fmt.Printf("\r%s:%d", pr.Host, r.Scan.Progress)
}

func (pr PrintResponses) Last(r scan.GetScansResponse) {
	fmt.Printf("\r%s:%d:%s:", pr.Host, r.Scan.Progress, r.Scan.Status)
}

type PackageVulnerability struct {
	Installed string
	Fixed     string
}

func ParseVulnerabilityFindings(value string) []PackageVulnerability {
	sl := strings.Split(value, "\n")
	pvs := make([]PackageVulnerability, 0, len(sl)/3)
	for _, mp := range sl {
		mip := strings.Split(mp, "Installed version:")
		if len(mip) == 2 {
			pvs = append(pvs, PackageVulnerability{
				Installed: strings.TrimSpace(mip[1]),
			})
		} else {
			mfp := strings.Split(mp, "Fixed version:")
			if len(mfp) == 2 {
				pvs[len(pvs)-1].Fixed = strings.TrimSpace(mfp[1])
			}
		}
	}
	return pvs
}

func ParseOSName(value string) string {
	prxlen := len("We are able to login and detect that you are running ")
	sfxlen := len(".\n")
	if len(value) > prxlen+sfxlen {
		result := value[prxlen : len(value)-sfxlen]
		return result
	}
	return ""
}

