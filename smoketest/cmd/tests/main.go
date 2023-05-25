// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/greenbone/notus-scanner/smoketest/products"
	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/nasl"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
)


func ParseHosts(hostPath string) ([]string, error) {
	result := make([]string, 0)
	f, err := os.Open(hostPath)
	if err != nil {
		return nil, err
	}
	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)
	for fs.Scan() {
		line := strings.TrimSpace(fs.Text())
		// ignore comments or emppty lines
		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	return result, nil
}

func main() {
	vtDIR := flag.String("vt-dir", "/var/lib/openvas/plugins", "A path to existing plugins.")
	policyPath := flag.String("policy-path", "/usr/local/src/policies", "path to policies.")
	ospdSocket := flag.String("u", "/run/ospd/ospd-openvas.sock", "path the ospd unix socket")
	productPath := flag.String("product-path", "/var/lib/notus/products", "path to the notus product definitions")
	hostsTxt := flag.String("hosts-txt", "/usr/local/src/notus/hosts.txt", "path to the hosts definition file.")
	flag.Parse()
	rc := 0
	naslCache, err := nasl.InitCache(*vtDIR)
	if err != nil {
		panic(err.Error())
	}
	policyCache, err := policies.InitCache(*policyPath)
	if err != nil {
		panic(err.Error())
	}
	lm, err := products.CreateLookupMap(*productPath)
	if err != nil {
		panic(err.Error())
	}
	hosts, err := ParseHosts(*hostsTxt)
	if err != nil {
		panic(err.Error())
	}
	protocoll := "unix"
	address := *ospdSocket
	co := connection.New(protocoll, address, "", "", false)
	gplt := products.GatherPackageListTests{
		NASLCache:     naslCache,
		PolicyCache:   policyCache,
		ProductLookup: lm,
		Sender:        co,
	}
	for _, host := range hosts {
		if hr := gplt.TestHost(host); hr.Success {
			fmt.Printf("success\n")
		} else {
			fmt.Printf("failed: %s\n", hr.Description)
			rc += 1
		}
	}
	os.Exit(rc)
}
