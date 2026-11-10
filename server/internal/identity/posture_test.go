package identity

import (
	"testing"

	"github.com/Neurvinch/SIEPMU/server/internal/config"
)

func TestBrowserVersion(t *testing.T) {
	cases := map[string]struct {
		fam string
		v   int
	}{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36":                         {"chrome", 131},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0": {"edge", 131},
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0":                                                        {"firefox", 133},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15":         {"safari", 18},
	}
	for ua, want := range cases {
		f, v := BrowserVersion(ua)
		if f != want.fam || v != want.v {
			t.Errorf("%s: got %s %d", ua, f, v)
		}
	}
}

func TestGeofence(t *testing.T) {
	boxes := []config.GeoBox{{Name: "Chennai", MinLat: 12.8, MaxLat: 13.3, MinLon: 80.0, MaxLon: 80.4}}
	in1, in2 := 13.08, 80.27
	out1, out2 := 28.6, 77.2
	if Geofence(&in1, &in2, boxes) != "inside" || Geofence(&out1, &out2, boxes) != "outside" || Geofence(nil, nil, boxes) != "unknown" {
		t.Fatal("geofence classification wrong")
	}
	if d := HaversineKm(13.08, 80.27, 28.6, 77.2); d < 1700 || d > 1800 {
		t.Fatalf("Chennai-Delhi distance %f", d)
	}
}
