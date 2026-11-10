package identity

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Neurvinch/SIEPMU/server/internal/config"
)

var uaPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"edge", regexp.MustCompile(`Edg/(\d+)`)},
	{"firefox", regexp.MustCompile(`Firefox/(\d+)`)},
	{"chrome", regexp.MustCompile(`Chrome/(\d+)`)},
	{"safari", regexp.MustCompile(`Version/(\d+)[\d.]* .*Safari/`)},
}

// BrowserVersion extracts the browser family and major version.
func BrowserVersion(ua string) (string, int) {
	for _, p := range uaPatterns {
		if m := p.re.FindStringSubmatch(ua); m != nil {
			v, _ := strconv.Atoi(m[1])
			return p.name, v
		}
	}
	return "unknown", 0
}

// Patched reports whether the client software meets the configured minimum.
// Non-browser clients (bridge, CLI) authenticate with mTLS, not this path.
func Patched(ua string, min map[string]int) bool {
	fam, v := BrowserVersion(ua)
	m, ok := min[fam]
	return ok && v >= m
}

// Geofence classifies a reported position against configured operating areas.
func Geofence(lat, lon *float64, boxes []config.GeoBox) string {
	if lat == nil || lon == nil {
		return "unknown"
	}
	if len(boxes) == 0 {
		return "unknown"
	}
	for _, b := range boxes {
		if *lat >= b.MinLat && *lat <= b.MaxLat && *lon >= b.MinLon && *lon <= b.MaxLon {
			return "inside"
		}
	}
	return "outside"
}

// HaversineKm is the great-circle distance between two points.
func HaversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}

// ParseGeo parses the X-SIEPMU-Geo header ("lat,lon").
func ParseGeo(h string) (*float64, *float64) {
	parts := strings.Split(h, ",")
	if len(parts) != 2 {
		return nil, nil
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return nil, nil
	}
	return &lat, &lon
}
