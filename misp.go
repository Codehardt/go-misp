package misp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	hc      *http.Client
	auth    string
	baseURL string
}

func New(httpClient *http.Client, baseURL string, auth string) (*Client, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &Client{
		hc:      httpClient,
		auth:    auth,
		baseURL: baseURL,
	}, nil
}

// Event in MISP
type Event struct {
	ID            int64       `json:"id,string"`
	Info          string      `json:"info"`
	Date          string      `json:"date"`
	Timestamp     string      `json:"timestamp"`
	ThreatLevelID int8        `json:"threat_level_id,string"`
	Published     bool        `json:"published"`
	Orgc          Org         `json:"Orgc"`
	Attributes    []Attribute `json:"attribute"`
	Tag           []Tag       `json:"tag"`
}

// Org / Orgc in Event
type Org struct {
	Name string `json:"name"`
}

// Attribute of Event
type Attribute struct {
	ID      int64  `json:"id,string"`
	Type    string `json:"type"`
	ToIDS   bool   `json:"to_ids"`
	Value   string `json:"value"`
	Deleted bool   `json:"deleted"`
}

// Tag of Event
type Tag struct {
	ID      int64  `json:"id,string"`
	Name    string `json:"name"`
	Color   string `json:"colour"`
	HideTag bool   `json:"hide_tag"`
}

// SearchEvents queries the MISP for events
func (c *Client) SearchEvents(tags, notTags []string, from, to, last, eventid string, metadata bool, timestamp *time.Time, limit, page int) (events []Event, err error) {
	src := struct {
		Tags      string `json:"tags,omitempty"`
		From      string `json:"from,omitempty"`
		To        string `json:"to,omitempty"`
		Last      string `json:"last,omitempty"`
		EventID   string `json:"eventid,omitempty"`
		Metadata  bool   `json:"metadata,omitempty"`
		Timestamp string `json:"timestamp,omitempty"`
		Limit     string `json:"limit"`
		Page      string `json:"page"`
	}{
		Tags:     chain(tags, notTags),
		From:     from,
		To:       to,
		Last:     last,
		EventID:  eventid,
		Metadata: metadata,
	}
	if timestamp != nil {
		src.Timestamp = strconv.FormatInt(timestamp.Unix(), 10)
	}
	if limit > 0 {
		src.Limit = strconv.Itoa(limit)
		src.Page = strconv.Itoa(page)
	}
	tgt := struct {
		Response []struct {
			Event Event `json:"Event"`
		} `json:"response"`
	}{}
	if err = c.httpPost("/events/restSearch/download/", &src, &tgt); err != nil {
		return
	}
	events = make([]Event, len(tgt.Response))
	for i, ev := range tgt.Response {
		events[i] = ev.Event
	}
	return
}

func chain(incl []string, excl []string) (chain string) {
	for i, elem := range incl {
		if i == 0 {
			chain = elem
		} else {
			chain += "&&" + elem
		}
	}
	for i, elem := range excl {
		if i == 0 && chain == "" {
			chain = "!" + elem
		} else {
			chain += "&&!" + elem
		}
	}
	return
}

func (c *Client) httpGet(path string, tgt interface{}) error {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.auth)
	b, err := c.httpDo(req)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, tgt)
}

func (c *Client) httpPost(path string, src interface{}, tgt interface{}) error {
	var body io.Reader
	if src != nil {
		b, err := json.Marshal(src)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest("POST", c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.auth)
	b, err := c.httpDo(req)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, tgt)
}

func (c *Client) httpDo(req *http.Request) ([]byte, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
