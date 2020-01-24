# go-misp

Query events and attributes from MISP with this Golang implementation.

## Example

```golang
mispClient, err := misp.New(&http.Client{/*...*/}, "https://<your-misp>/", "<auth key>")
if err != nil {
    panic(err)
}
events, err := mispClient.SearchEvents(nil, nil, "", "", "", "", false)
if err != nil {
    panic(err)
}
```
