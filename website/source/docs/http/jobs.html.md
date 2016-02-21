---
layout: "http"
page_title: "HTTP API: /v1/jobs"
sidebar_current: "docs-http-jobs"
description: |-
  The '/1/jobs' endpoint is used list jobs and register new ones.
---

# /v1/jobs

The `jobs` endpoint is used to query the status of existing jobs in Nomad
and to register new jobs. By default, the agent's local region is used;
another region can be specified using the `?region=` query parameter.

## GET

<dl>
  <dt>Description</dt>
  <dd>
    Lists all the jobs registered with Nomad.
  </dd>

  <dt>Method</dt>
  <dd>GET</dd>

  <dt>URL</dt>
  <dd>`/v1/jobs`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">prefix</span>
        <span class="param-flags">optional</span>
        Filter jobs based on an identifier prefix.
      </li>
    </ul>
  </dd>

  <dt>Blocking Queries</dt>
  <dd>
    [Supported](/docs/http/index.html#blocking-queries)
  </dd>

  <dt>Returns</dt>
  <dd>

    ```javascript
    [
    {
        "ID": "binstore-storagelocker",
        "Name": "binstore-storagelocker",
        "Type": "service",
        "Priority": 50,
        "Status": "",
        "StatusDescription": "",
        "CreateIndex": 14,
        "ModifyIndex": 14
    },
    ...
    ]
    ```

  </dd>
</dl>

## PUT / POST

<dl>
  <dt>Description</dt>
  <dd>
    Registers a new job.
  </dd>

  <dt>Method</dt>
  <dd>PUT or POST</dd>

  <dt>URL</dt>
  <dd>`/v1/jobs`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">Job</span>
        <span class="param-flags">required</span>
        The JSON definition of the job. The general structure is given
        by the [job specification](/docs/jobspec/index.html), and matches
        the return response of [GET against `/v1/job/<ID>`](/docs/http/job.html).
      </li>
    </ul>
    <ul>
    ```javascript
    {
      "Datacenters": [
        "dc1"
      ],
      "AllAtOnce": false,
      "Priority": 50,
      "Type": "service",
      "Name": "example",
      "Region": "global",
      "Constraints": [
        {
          "Operand": "=",
          "RTarget": "linux",
          "LTarget": "${attr.kernel.name}"
        }
      ],
      "TaskGroups": [
        {
          "Meta": null,
          "Tasks": [
            {
              "LogConfig": {
                "MaxFileSizeMB": 10,
                "MaxFiles": 10
              },
              "KillTimeout": 5e+09,
              "Name": "redis",
              "Driver": "docker",
              "Config": {
                "port_map": [
                  {
                    "db": 6379
                  }
                ],
                "image": "redis:latest"
              },
              "Env": {
                  "foo": "bar"
              },
              "Services": [
                {
                  "Checks": [
                    {
                      "Timeout": 2e+09,
                      "Interval": 1e+10,
                      "Protocol": "",
                      "Path": "",
                      "Script": "",
                      "Type": "tcp",
                      "Name": "alive"
                    }
                  ],
                  "PortLabel": "db",
                  "Tags": [
                    "global",
                    "cache"
                  ],
                  "Name": "cache-redis"
                }
              ],
              "Constraints": null,
              "Resources": {
                "Networks": [
                  {
                    "DynamicPorts": [
                      {
                        "Value": 0,
                        "Label": "db"
                      }
                    ],
                    "ReservedPorts": null,
                    "MBits": 10,
                    "IP": "",
                    "CIDR": "",
                    "Device": ""
                  }
                ],
                "IOPS": 0,
                "DiskMB": 300,
                "MemoryMB": 256,
                "CPU": 500
              },
              "Meta": {
                  "foo": "bar",
                  "baz": "pipe"
              }
            }
          ],
          "RestartPolicy": {
            "Mode": "delay",
            "Delay": 2.5e+10,
            "Interval": 3e+11,
            "Attempts": 10
          },
          "Constraints": null,
          "Count": 1,
          "Name": "cache"
        }
      ],
      "Update": {
        "MaxParallel": 1,
        "Stagger": 1e+10
      },
      "Periodic": {
          "Enabled": true,
          "Spec": "0 0 0/2 * * ?",
          "SpecType": "cron",
          "ProhibitOverlap": true
      },
      "Meta": {
          "foo": "bar",
          "baz": "pipe"
      }
    }
    ```
    </ul>
  </dd>

  <dt>Returns</dt>
  <dd>

    ```javascript
    {
    "EvalID": "d092fdc0-e1fd-2536-67d8-43af8ca798ac",
    "EvalCreateIndex": 35,
    "JobModifyIndex": 34,
    }
    ```

  </dd>
</dl>
