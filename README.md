# OCI Image Unpacker

离线排查容器文件缺失时，从交付镜像还原最终根文件系统的服务。
上传仅含单个 manifest 的 OCI Image Layout tar，当次请求返回还原后的 `rootfs.tar`；
也可以选择当次返回**逐层字节诊断 JSON**——回答"安装缓存已被上层删除，镜像仍带着旧字节"
这类问题：每个层写了多少字节、多少最终保留、多少在哪一层被作废。

## 快速开始（docker compose）

```bash
docker compose up --build
```

服务监听 <http://localhost:8000>，打开 <http://localhost:8000/docs>：

1. 先调 `GET /sample-image` 下载样例镜像 `sample-image.tar`（Swagger 里点 "Download file"）；
2. 再在 `POST /unpack` 里上传该 tar，响应即为 `rootfs.tar`；
3. 同一把 `stats` 勾为 `true` 再上传，响应当次的诊断 JSON；
4. 复核方把这份 JSON 上传到 `POST /verify-stats`，无需原镜像即可重算并核对逐层汇总。

命令行等价操作：

```bash
curl -OJ http://localhost:8000/sample-image          # 下载样例镜像
curl -F "file=@sample-image.tar" -OJ \
     http://localhost:8000/unpack                    # 得到 rootfs.tar
tar -tf rootfs.tar                                   # 查看还原结果

curl -F "file=@sample-image.tar" \
     "http://localhost:8000/unpack?stats=true"       # 得到诊断 JSON（存为 stats.json）
curl -F "file=@stats.json" \
     http://localhost:8000/verify-stats              # 复核：重算并核对逐层汇总
```

本地开发（不用 Docker）：

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest                 # 运行测试
```

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/unpack` | 上传 OCI Image Layout tar（单 manifest），返回 `rootfs.tar`；任何校验/解包失败返回 400，不返回残缺文件系统 |
| `POST` | `/unpack?stats=true` | 同上，但当次返回逐层字节诊断 JSON（不落盘展开文件内容） |
| `POST` | `/verify-stats` | 上传诊断 JSON，重算逐层汇总并指出不一致；文档结构非法返回 400 |
| `GET` | `/sample-image` | 下载样例镜像（含删除、opaque、硬链接覆盖） |
| `GET` | `/healthz` | 健康检查 |

## 诊断 JSON（`stats=true`）

```json
{
  "schema": "oci-unpacker-stats/1",
  "writes": [{"id": 1, "layer": 1, "bytes": 24}],
  "invalidations": [{"write": 1, "layer": 2}],
  "layers": [
    {"layer": 1, "written_bytes": 24, "retained_bytes": 0,
     "invalidated_in": {"2": 24}}
  ]
}
```

- **层号从 1 起**，按 manifest 层序；`layers` 汇总逐层（1..N 连续）给出
  `written_bytes`（该层普通文件写入字节）、`retained_bytes`（最终保留字节）
  与 `invalidated_in`（该层写入的字节按**失效层**分组）。
- **writes**：每次普通文件写入一条记录（编号从 1 递增、层号、字节数）。
  同层多次写到同一位置逐次计数；0 字节文件也记录。
- **invalidations**：每条记录给出一个写入编号与其**最后一个直接引用消失**
  的层号（覆盖、被目录/符号链接替换、whiteout、opaque、父目录被替换）。
- **硬链接不新增写入**，只是给已有写入加一份引用：覆盖硬链接的一端时，
  另一端仍引用旧字节，该写入不失效；只有最后一份引用消失才记失效。
- whiteout / opaque 与普通解包**共用同一份叠层逻辑**（先扫描整层、删除只
  作用于下层、再写入本层），统计限非稀疏普通文件、目录、符号链接与硬链接；
  稀疏文件、fifo、设备节点等其它类型在统计模式下直接报错。
- 统计直接使用校验过的层 tar（gzip 层校验 diff_id 时已解压），不另造层 tar，
  也绝不把文件内容展开到磁盘；校验或叠层失败只返回 400 错误。

## 复核（`/verify-stats`）

复核方上传诊断 JSON 后，服务仅凭文档本身重算逐层汇总并返回
`{"valid": bool, "errors": [...], "layers": [...重算结果...]}`。
以下情况会在 `errors` 中指出（文档结构非法则直接 400）：

- **写入编号重复**；
- **重复失效**（同一写入被失效多次）；
- **失效无对应写入**，或**失效层早于写入层**（同层失效合法）；
- **汇总不符**（`written_bytes` / `retained_bytes` / `invalidated_in`
  与重算结果不一致，或层号不是从 1 起连续编号）。

## 校验与还原语义

- **完整性校验**：index.json 引用的 manifest blob、manifest 引用的 config 与
  各 layer blob 都会核对**存在性、字节大小、SHA-256**；每个 layer 解压后
  （gzip 层先解压）再与 config 中 `rootfs.diff_ids` 逐一核对。层数与
  diff_ids 数量不一致、摘要不符、缺块、损坏，整次请求报错。
- **层格式**：支持未压缩层（`...layer.v1.tar`）与 gzip 层
  （`...layer.v1.tar+gzip`，含 docker 对应 mediaType）。
- **按清单层序还原**：普通文件、目录、符号链接、硬链接与权限位（含
  setuid/sgid/sticky）；目录权限与 mtime 在全部层应用完后统一设置，避免
  只读目录阻断同层/上层写入。
- **whiteout / opaque**：每层先扫描全部条目，把 `.wh.<name>` 与
  `.wh..wh..opq` 的删除动作**只作用于下层文件系统**，然后再写入本层新
  内容。因此删除标记在层内的位置（文件前/后）不会影响同层新增文件。
- **硬链接覆盖安全**：新文件先写临时文件再 `rename` 替换，绝不原地截断，
  所以覆盖硬链接的一端时，另一端保留原字节。输出 tar 中仍共享 inode 的
  硬链接会以硬链接条目保留。
- **路径安全**：条目路径拒绝绝对路径与 `..`；符号链接目标（绝对目标按
  rootfs 内解释）与硬链接目标经解析后必须落在隔离目录内，写入前再随
  符号链接逐层解析校验，任何逃逸都会让整次请求失败。
- **请求隔离**：每个请求使用独立临时目录，失败即清理，成功响应发送后
  清理；请求之间互不影响。

## 样例镜像内容

两层（第一层 gzip，第二层未压缩），用于验证上述语义：

- 下层文件 `app/config.txt`、`app/data/remove.txt` 被 whiteout 删除；
- `secret/` 被标记 opaque：下层的 `secret/token.txt` 消失，同层新增的
  `secret/public.txt` 保留；
- `app/data/rebuilt.txt` 在同层先写新内容、后出现其 whiteout —— 新内容
  必须保留；
- `bin/tool` 与 `bin/tool-link` 在下层是同一硬链接，上层只覆盖
  `bin/tool`（`tool-v2`），`bin/tool-link` 必须仍是 `tool-v1`；
- 相对符号链接 `bin/tool-alias -> tool` 与绝对符号链接
  `etc/motd-link -> /etc/motd`；
- 权限位：`bin/tool` 0755、`secret/` 0700。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `UNPACK_WORKDIR` | `$TMPDIR/oci-unpacker` | 请求临时目录与样例镜像存放位置 |
