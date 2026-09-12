```
📁 プロジェクトルート/
├── 📁 src/
│   └── 📁 main/
│       ├── 📁 java/
│       │   └── com/example/demo/
│       │       └── config/ServletConfig.java
│       │
│       ├── 📁 resources/ (★ここには Java の設定ファイルや i18n メッセージ等だけを置く)
│       │
│       └── 📁 webapp/ (★MavenデフォルトのWeb公開領域)
│           ├── 📁 css/ (★ th:href="@{/css/main.css}" でスマートに呼べる)
│           │   └── 📄 main.css
│           ├── 📁 js/
│           │   └── 📄 main.js
│           │
│           └── 📁 WEB-INF/ (★ブラウザから絶対に見えない安全地帯)
│               └── 📁 templates/ (★Thymeleaf テンプレートをここに集約)
│                   └── 📄 index.html
```