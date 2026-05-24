package osv

import (
	"fmt"
	"math"
	"strings"
)

// cvssV3BaseScore parses a CVSS v3.0/v3.1 vector string and returns the base
// score per the standard formula (https://www.first.org/cvss/v3.1/specification-document).
//
// Only the eight base metrics are used (AV, AC, PR, UI, S, C, I, A); temporal
// and environmental metrics, if present, are ignored. The leading "CVSS:3.x/"
// prefix is optional. An error is returned if a required metric is missing or a
// value is unrecognized.
func cvssV3BaseScore(vector string) (float64, error) {
	metrics, err := parseCVSSVector(vector)
	if err != nil {
		return 0, err
	}

	av, err := lookup(metrics, "AV", map[string]float64{
		"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2,
	})
	if err != nil {
		return 0, err
	}
	ac, err := lookup(metrics, "AC", map[string]float64{
		"L": 0.77, "H": 0.44,
	})
	if err != nil {
		return 0, err
	}
	ui, err := lookup(metrics, "UI", map[string]float64{
		"N": 0.85, "R": 0.62,
	})
	if err != nil {
		return 0, err
	}
	scope, ok := metrics["S"]
	if !ok {
		return 0, fmt.Errorf("cvss: missing metric S")
	}
	scopeChanged := scope == "C"
	if scope != "C" && scope != "U" {
		return 0, fmt.Errorf("cvss: bad value S:%s", scope)
	}

	// Privileges Required is scope-dependent.
	prRaw, ok := metrics["PR"]
	if !ok {
		return 0, fmt.Errorf("cvss: missing metric PR")
	}
	var pr float64
	switch prRaw {
	case "N":
		pr = 0.85
	case "L":
		if scopeChanged {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scopeChanged {
			pr = 0.5
		} else {
			pr = 0.27
		}
	default:
		return 0, fmt.Errorf("cvss: bad value PR:%s", prRaw)
	}

	impactValues := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, err := lookup(metrics, "C", impactValues)
	if err != nil {
		return 0, err
	}
	i, err := lookup(metrics, "I", impactValues)
	if err != nil {
		return 0, err
	}
	a, err := lookup(metrics, "A", impactValues)
	if err != nil {
		return 0, err
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0, nil
	}

	var base float64
	if scopeChanged {
		base = roundUp1(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = roundUp1(math.Min(impact+exploitability, 10))
	}
	return base, nil
}

// parseCVSSVector splits a vector into metric=value pairs, tolerating an
// optional "CVSS:3.x" leading segment.
func parseCVSSVector(vector string) (map[string]string, error) {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return nil, fmt.Errorf("cvss: empty vector")
	}
	out := map[string]string{}
	for _, seg := range strings.Split(vector, "/") {
		if seg == "" {
			continue
		}
		kv := strings.SplitN(seg, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("cvss: malformed segment %q", seg)
		}
		key, val := kv[0], kv[1]
		if key == "CVSS" {
			// Version marker; accept 3.0 / 3.1, reject others explicitly.
			if val != "3.0" && val != "3.1" {
				return nil, fmt.Errorf("cvss: unsupported version %q", val)
			}
			continue
		}
		out[key] = val
	}
	return out, nil
}

func lookup(metrics map[string]string, key string, table map[string]float64) (float64, error) {
	v, ok := metrics[key]
	if !ok {
		return 0, fmt.Errorf("cvss: missing metric %s", key)
	}
	score, ok := table[v]
	if !ok {
		return 0, fmt.Errorf("cvss: bad value %s:%s", key, v)
	}
	return score, nil
}

// roundUp1 implements the CVSS v3.1 "Roundup" function to one decimal place,
// avoiding floating-point drift by working in integer hundredths.
func roundUp1(x float64) float64 {
	intInput := int(math.Round(x * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return (math.Floor(float64(intInput)/10000) + 1) / 10
}
