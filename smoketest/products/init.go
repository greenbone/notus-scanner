// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package products

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type FixedPackage struct {
	Name        string `json:"name"`
	FullVersion string `json:"full_version"`
	FullName    string `json:"full_name"`
	Specifier   string `json:"specifier"`
}

type Advisory struct {
	OID           string         `json:"oid"`
	FixedPackages []FixedPackage `json:"fixed_packages"`
}

func (a *Advisory) FindByName(name string) *FixedPackage {
	for _, fp := range a.FixedPackages {
		if fp.Name == name {
			return &fp
		}
	}
	return nil
}

func (a *Advisory) FindByFullVersion(fullversion string) *FixedPackage {
	for _, fp := range a.FixedPackages {
		if fp.FullVersion == fullversion {
			return &fp
		}
	}
	return nil
}

func (a *Advisory) FindByFullName(fullname string) *FixedPackage {
	for _, fp := range a.FixedPackages {
		// currently it seems there is a bug in notus swallowing the last digit of a -version:
		// aaa_libraries-15.0-x86_64-19 becomes aaa_libraries-15.0-x86_64-1
		if strings.HasPrefix(fp.FullName, fullname) {
			return &fp
		}
	}
	return nil
}

func (a *Advisory) Find(value string) *FixedPackage {
	if strings.HasPrefix(value, ">") || strings.HasPrefix(value, "<") || strings.HasPrefix(value, "=") {
		value = value[1:]
		if strings.HasPrefix(value, "=") {
			value = value[1:]
		}
	}
	if found := a.FindByFullName(value); found != nil {
		return found
	}
	if found := a.FindByFullVersion(value); found != nil {
		return found
	}
	return a.FindByName(value)
}

type Product struct {
	Version     string     `json:"version"`
	PackageType string     `json:"package_type"`
	OSName      string     `json:"product_name"`
	Advisories  []Advisory `json:"advisories"`
}

func (p *Product) FindAdvisoryByOID(oid string) *Advisory {
	for _, a := range p.Advisories {
		if a.OID == oid {
			return &a
		}
	}
	return nil
}

func CreateLookupMap(npp string) (map[string]Product, error) {
	result := make(map[string]Product)
	files, err := ioutil.ReadDir(npp)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !f.IsDir() {
			if strings.HasSuffix(f.Name(), ".notus") {
				nf, err := os.Open(path.Join(npp, f.Name()))
				if err != nil {
					return nil, err
				}
				var r Product
				if err := json.NewDecoder(nf).Decode(&r); err != nil {
					return nil, err
				}
				result[r.OSName] = r

			}
		}
	}
	return result, nil
}
