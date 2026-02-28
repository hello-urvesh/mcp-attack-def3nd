## Config for Hello 

``` bash
{
  "mcpServers": {
    "hello-world": {
      "command": "python",
      "args": [
        "C:\\Users\\Urvesh\\Documents\\nullcon-mcp-lab\\build-mcp\\hello-mcp\\server.py",
        "--stdio"
      ]
    }
  },
  "preferences": {
    "coworkWebSearchEnabled": true,
    "coworkScheduledTasksEnabled": true,
    "sidebarMode": "chat"
  }
}
``` 
## Config for ELK

``` bash
{
  "mcpServers": {
    "elasticsearch": {
      "command": "python",
      "args": [
        "C:\\<REPLACE-ME-WITH-ACTUAL-PATH\\es_mcp_server.py",
        "--stdio"
      ]
    }
  }
}
```
