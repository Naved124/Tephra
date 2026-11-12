// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// LabLabel must be on every node of a cluster the harness may attack.
const LabLabel = "tephra.dev/lab"

// Cluster reaches the lab cluster through kubectl, and Loki through
// Grafana.
type Cluster struct {
	// Context is the kubectl context; empty uses the current one.
	Context string
	// Namespace and Release locate the Tephra installation.
	Namespace string
	Release   string

	grafana  string // base URL of the port-forward
	user     string
	password string
	forward  *exec.Cmd
}

func (c *Cluster) kubectl(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	if c.Context != "" {
		args = append([]string{"--context", c.Context}, args...)
	}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

type nodeList struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			NodeInfo struct {
				KernelVersion string `json:"kernelVersion"`
			} `json:"nodeInfo"`
		} `json:"status"`
	} `json:"items"`
}

// checkLab decides from a node list whether the cluster is a lab.
func checkLab(raw []byte) (kernel string, err error) {
	var nodes nodeList
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return "", fmt.Errorf("read node list: %w", err)
	}
	if len(nodes.Items) == 0 {
		return "", fmt.Errorf("the cluster has no nodes")
	}
	for _, n := range nodes.Items {
		if n.Metadata.Labels[LabLabel] != "true" {
			return "", fmt.Errorf("node %s is not labelled %s=true: this is not a lab cluster, and the harness runs attack techniques. Refusing", n.Metadata.Name, LabLabel)
		}
	}
	return nodes.Items[0].Status.NodeInfo.KernelVersion, nil
}

// RequireLab fails unless every node carries the lab label. There is no way
// to switch this off: the scenarios are real attack techniques.
func (c *Cluster) RequireLab(ctx context.Context) (kernel string, err error) {
	raw, err := c.kubectl(ctx, nil, "get", "nodes", "-o", "json")
	if err != nil {
		return "", err
	}
	return checkLab(raw)
}

// Connect opens a port-forward to Grafana and reads its credentials. The
// password stays in this process; it is never put on a command line.
func (c *Cluster) Connect(ctx context.Context) error {
	secret, err := c.kubectl(ctx, nil, "-n", c.Namespace, "get", "secret", c.Release+"-grafana", "-o", "json")
	if err != nil {
		return err
	}
	var s struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(secret, &s); err != nil {
		return err
	}
	for key, dst := range map[string]*string{"admin-user": &c.user, "admin-password": &c.password} {
		v, err := base64.StdEncoding.DecodeString(s.Data[key])
		if err != nil || len(v) == 0 {
			return fmt.Errorf("secret %s-grafana has no %s", c.Release, key)
		}
		*dst = string(v)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	args := []string{"-n", c.Namespace, "port-forward", "service/" + c.Release + "-grafana", strconv.Itoa(port) + ":3000"}
	if c.Context != "" {
		args = append([]string{"--context", c.Context}, args...)
	}
	c.forward = exec.Command("kubectl", args...)
	if err := c.forward.Start(); err != nil {
		return err
	}
	c.grafana = "http://127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.get(ctx, "/api/health", nil); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	c.Close()
	return fmt.Errorf("no answer from Grafana through the port-forward")
}

// Close ends the port-forward.
func (c *Cluster) Close() {
	if c.forward != nil && c.forward.Process != nil {
		_ = c.forward.Process.Kill()
		_, _ = c.forward.Process.Wait()
		c.forward = nil
	}
}

func (c *Cluster) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	u := c.grafana + path
	if query != nil {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	return body, nil
}

// Alert is the part of an alert record the harness reads.
type Alert struct {
	TS   string `json:"ts"`
	Type string `json:"type"`
	Rule struct {
		ID    string `json:"id"`
		Level string `json:"level"`
	} `json:"rule"`
	Process struct {
		Image       string `json:"Image"`
		CommandLine string `json:"CommandLine"`
	} `json:"process"`
	Container *struct {
		Name string `json:"name"`
	} `json:"container"`
	K8s struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
	} `json:"k8s"`
	// Line is the whole record as stored.
	Line string `json:"-"`
}

// Time is the event's own time.
func (a *Alert) Time() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, a.TS)
	return t
}

// Alerts returns the alerts matching a LogQL stream selector since a time,
// oldest first.
func (c *Cluster) Alerts(ctx context.Context, selector string, since time.Time) ([]*Alert, error) {
	body, err := c.get(ctx, "/api/datasources/proxy/uid/loki/loki/api/v1/query_range", url.Values{
		"query":     {selector},
		"start":     {strconv.FormatInt(since.UnixNano(), 10)},
		"limit":     {"5000"},
		"direction": {"forward"},
	})
	if err != nil {
		return nil, err
	}
	var res struct {
		Data struct {
			Result []struct {
				Values [][2]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	var out []*Alert
	for _, stream := range res.Data.Result {
		for _, v := range stream.Values {
			a := &Alert{Line: v[1]}
			if json.Unmarshal([]byte(v[1]), a) == nil && a.Rule.ID != "" {
				out = append(out, a)
			}
		}
	}
	sortAlerts(out)
	return out, nil
}

// Drops is the number of events the kernel side dropped, summed over every
// agent and event type.
func (c *Cluster) Drops(ctx context.Context) (uint64, error) {
	pods, err := c.kubectl(ctx, nil, "-n", c.Namespace, "get", "pods",
		"-l", "app.kubernetes.io/component=agent,app.kubernetes.io/instance="+c.Release,
		"--field-selector", "status.phase=Running", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, pod := range strings.Fields(string(pods)) {
		metrics, err := c.kubectl(ctx, nil, "get", "--raw", "/api/v1/namespaces/"+c.Namespace+"/pods/"+pod+":9090/proxy/metrics")
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(metrics), "\n") {
			if strings.HasPrefix(line, "tephra_kernel_events_total") && strings.Contains(line, `outcome="dropped"`) {
				if i := strings.LastIndexByte(line, ' '); i > 0 {
					n, _ := strconv.ParseUint(line[i+1:], 10, 64)
					total += n
				}
			}
		}
	}
	return total, nil
}

// SensorVersion is the version the agents report about themselves, with the
// image they run.
func (c *Cluster) SensorVersion(ctx context.Context) string {
	image, err := c.kubectl(ctx, nil, "-n", c.Namespace, "get", "daemonset", c.Release+"-agent",
		"-o", "jsonpath={.spec.template.spec.containers[0].image}")
	if err != nil {
		return "unknown"
	}
	pods, err := c.kubectl(ctx, nil, "-n", c.Namespace, "get", "pods",
		"-l", "app.kubernetes.io/component=agent,app.kubernetes.io/instance="+c.Release,
		"--field-selector", "status.phase=Running", "-o", "jsonpath={.items[0].metadata.name}")
	if err == nil && len(pods) > 0 {
		metrics, err := c.kubectl(ctx, nil, "get", "--raw", "/api/v1/namespaces/"+c.Namespace+"/pods/"+string(pods)+":9090/proxy/metrics")
		if err == nil {
			if v := buildVersion(string(metrics)); v != "" {
				return v + " (" + string(image) + ")"
			}
		}
	}
	return string(image)
}

// buildVersion extracts the version label of tephra_build_info.
func buildVersion(metrics string) string {
	const prefix = `tephra_build_info{version="`
	for _, line := range strings.Split(metrics, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			if i := strings.IndexByte(rest, '"'); i >= 0 {
				return rest[:i]
			}
		}
	}
	return ""
}

// exec runs a script in a container, feeding it on stdin so that nothing of
// it has to be quoted.
func (c *Cluster) execScript(ctx context.Context, namespace string, t Target, script string) ([]byte, error) {
	f, err := os.Open(script)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	args := []string{"-n", namespace, "exec", "-i", t.Pod}
	if t.Container != "" {
		args = append(args, "-c", t.Container)
	}
	return c.kubectl(ctx, f, append(args, "--", "sh", "-s")...)
}
