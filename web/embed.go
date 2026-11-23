// Package web 把 Vue 构建产物嵌入 Go 二进制，并提供 SPA 静态文件服务。
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler 返回静态文件处理器，未知路径回退到 index.html。
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "." {
			// 只把真实文件交给 FileServer：目录（例如 /assets/）会触发目录列表，
			// 泄露构建产物清单，这里统一回退到 SPA 首页。
			if f, err := sub.Open(p); err == nil {
				info, statErr := f.Stat()
				f.Close()
				if statErr == nil && !info.IsDir() {
					// assets 下的文件名带内容哈希，可长期缓存；index.html 必须每次回源校验，
					// 否则升级后浏览器会拿旧页面去引用已经不存在的构建产物。
					if strings.HasPrefix(p, "assets/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					} else {
						w.Header().Set("Cache-Control", "no-cache")
					}
					fileServer.ServeHTTP(w, r)
					return
				}
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(index)
	})
}
