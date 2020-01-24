package misp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

var eventSearchResult = `
{
	"response": [{
		"Event": {
			"id": "1488",
			"orgc_id": "2",
			"org_id": "2",
			"date": "2020-01-22",
			"threat_level_id": "3",
			"info": "Test Event",
			"published": false,
			"uuid": "5e287d09-b3a0-4741-bbea-7ae3ac1c1da0",
			"attribute_count": "1",
			"analysis": "0",
			"timestamp": "1579771919",
			"distribution": "0",
			"proposal_email_lock": false,
			"locked": false,
			"publish_timestamp": "0",
			"sharing_group_id": "0",
			"disable_correlation": false,
			"extends_uuid": "",
			"event_creator_email": "<hidden-email>",
			"Org": {
				"id": "2",
				"name": "Test Org",
				"uuid": "5b15605c-4248-4f8f-ac51-04c0ac1c1da0"
			},
			"Orgc": {
				"id": "2",
				"name": "Test Org",
				"uuid": "5b15605c-4248-4f8f-ac51-04c0ac1c1da0"
			},
			"Attribute": [{
				"id": "193850",
				"type": "yara",
				"category": "Payload delivery",
				"to_ids": true,
				"uuid": "5e287dc3-39bc-423b-9113-7e60ac1c1da0",
				"event_id": "1488",
				"distribution": "5",
				"timestamp": "1579711939",
				"comment": "",
				"sharing_group_id": "0",
				"deleted": false,
				"disable_correlation": false,
				"object_id": "0",
				"object_relation": null,
				"value": "rule Test {condition: uint16(0) == 0x5a4d}",
				"Galaxy": [],
				"ShadowAttribute": []
			}],
			"ShadowAttribute": [],
			"RelatedEvent": [],
			"Galaxy": [],
			"Object": [],
			"Tag": [{
				"id": "6",
				"name": "test_tag",
				"colour": "#140303",
				"exportable": true,
				"user_id": false,
				"hide_tag": false
			}]
		}
	}]
}
`

type server struct{}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "test-auth" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	if strings.TrimSuffix(r.URL.Path, "/") == "/events/restSearch/download" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(eventSearchResult))
	} else {
		http.Error(w, "", http.StatusNotFound)
		return
	}
}

func TestSearchEvents(t *testing.T) {
	// start a test server
	s := httptest.NewServer(&server{})
	defer s.Close()
	client, err := New(s.Client(), s.URL, "test-auth")
	if err != nil {
		t.Fatal(err)
	}
	events, err := client.SearchEvents(nil, nil, "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []Event{{
		ID:            "1488",
		Info:          "Test Event",
		Date:          "2020-01-22",
		ThreadLevelID: "3",
		Published:     false,
		Orgc: Org{
			Name: "Test Org",
		},
		Attributes: []Attribute{{
			ID:      "193850",
			Type:    "yara",
			ToIDS:   true,
			Value:   "rule Test {condition: uint16(0) == 0x5a4d}",
			Deleted: false,
		}},
		Tag: []Tag{{
			Name:    "test_tag",
			HideTag: false,
		}},
	}}) {
		t.Fatalf("not deep equal, got: %#v", events)
	}
}

func ExampleChain() {
	fmt.Println(chain(nil, nil))
	fmt.Println(chain([]string{"+tag"}, nil))
	fmt.Println(chain(nil, []string{"-tag"}))
	fmt.Println(chain([]string{"+tag"}, []string{"-tag"}))
	fmt.Println(chain([]string{"+tag1", "+tag2"}, nil))
	fmt.Println(chain(nil, []string{"-tag1", "-tag2"}))
	fmt.Println(chain([]string{"+tag1", "+tag2"}, []string{"-tag1", "-tag2"}))
	// Output:
	//
	// +tag
	// !-tag
	// +tag&&!-tag
	// +tag1&&+tag2
	// !-tag1&&!-tag2
	// +tag1&&+tag2&&!-tag1&&!-tag2
}
