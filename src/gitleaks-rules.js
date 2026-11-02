/* Gitleaks rules, pinned at 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c.
 * MIT (c) 2019 Zachary Rice. See licenses/GITLEAKS.txt in the extension.
 * Go case folding, ASCII whitespace and strict end anchors are adapted for Chrome 120. */
(() => {
  'use strict';
  globalThis.SecretShieldRules = Object.freeze({
  "source": "https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml",
  "sourceRegex": "(?i)[\\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
  "globalAllowlists": [
    {
      "condition": "OR",
      "regexTarget": "secret",
      "regexes": [
        "^[tT][rR][uU][eE]|[fF][aA][lL][sSſ][eE]|[nN][uU][lL][lL](?![\\s\\S])",
        "^(?:[aA]+|[bB]+|[cC]+|[dD]+|[eE]+|[fF]+|[gG]+|[hH]+|[iI]+|[jJ]+|[kKK]+|[lL]+|[mM]+|[nN]+|[oO]+|[pP]+|[qQ]+|[rR]+|[sSſ]+|[tT]+|[uU]+|[vV]+|[wW]+|[xX]+|[yY]+|[zZ]+|\\*+|\\.+)(?![\\s\\S])",
        "^\\$(?:\\d+|{\\d+})(?![\\s\\S])",
        "^\\$(?:[A-Z_]+|[a-z_]+)(?![\\s\\S])",
        "^\\${(?:[A-Z_]+|[a-z_]+)}(?![\\s\\S])",
        "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}(?![\\s\\S])",
        "^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}(?![\\s\\S])",
        "^%(?:[A-Z_]+|[a-z_]+)%(?![\\s\\S])",
        "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX](?![\\s\\S])",
        "^\\{\\d{0,2}}(?![\\s\\S])",
        "^@(?:[A-Z_]+|[a-z_]+)@(?![\\s\\S])",
        "^/Users/[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]+/[\\w .-/]+(?![\\s\\S])",
        "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+(?![\\s\\S])"
      ],
      "stopwords": [
        "014df517-39d1-4453-b7b3-9930c563627c", "abcdefghijklmnopqrstuvwxyz"
      ],
      "paths": [
        "gitleaks\\.toml",
        "(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
        "(?i)\\.(?:eot|[ot]tf|woff2?)$",
        "(?i)\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
        "go\\.(?:mod|sum|work(?:\\.sum)?)$",
        "(?:^|/)vendor/modules\\.txt$",
        "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$",
        "(?:^|/)gradlew(?:\\.bat)?$",
        "(?:^|/)gradle\\.lockfile$",
        "(?:^|/)mvnw(?:\\.cmd)?$",
        "(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$",
        "(?:^|/)node_modules(?:/.*)?$",
        "(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$",
        "(?:^|/)bower_components(?:/.*)?$",
        "(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$",
        "(?:^|/)javascript\\.json$",
        "(?:^|/)(?:Pipfile|poetry)\\.lock$",
        "(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
        "(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$",
        "(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$",
        "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$",
        "\\.gem$",
        "verification-metadata\\.xml",
        "Database.refactorlog",
        "(?:^|/)\\.git$"
      ]
    }
  ],
  "rules": [
    {
      "id": "generic-api-key",
      "description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][cC][cC][eE][sSſ][sSſ]|[aA][uU][tT][hH]|(?:[Aa]pi|API)|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[cC][rR][eE][dD][sSſ]|[kKK][eE][yY]|[pP][aA][sSſ][sSſ][wW](?:[oO][rR])?[dD]|[sSſ][eE][cC][rR][eE][tT]|[tT][oO][kKK][eE][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([A-Za-z0-9_ſK.=-]{10,150}|[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9][aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9+/]{11,}={0,3})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 3.5,
      "keywords": [
        "access",
        "api",
        "auth",
        "key",
        "credential",
        "creds",
        "passwd",
        "password",
        "secret",
        "token"
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [
            "^[a-zA-Z_.-]+(?![\\s\\S])"
          ],
          "stopwords": [],
          "paths": []
        },
        {
          "condition": "OR",
          "regexTarget": "match",
          "regexes": [
            "(?:[aA][cC][cC][eE][sSſ][sSſ](?:[iI][bB][iI][lL][iI][tT][yY]|[oO][rR])|[aA][cC][cC][eE][sSſ][sSſ][_.-]?[iI][dD]|[rR][aA][nN][dD][oO][mM][_.-]?[aA][cC][cC][eE][sSſ][sSſ]|[aA][pP][iI][_.-]?(?:[iI][dD]|[nN][aA][mM][eE]|[vV][eE][rR][sSſ][iI][oO][nN])|[rR][aA][pP][iI][dD]|[cC][aA][pP][iI][tT][aA][lL]|[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9-]*?[aA][pP][iI][aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9-]*?:[jJ][aA][rR]:|[aA][uU][tT][hH][oO][rR]|[Xx]-[Mm][Ssſ]-[Ee][xX][cC][hH][aA][nN][gG][eE]-[Oo][rR][gG][aA][nN][iI][zZ][aA][tT][iI][oO][nN]-[Aa][uU][tT][hH]|[Aa][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][iI][oO][nN]-[Rr][eE][sSſ][uU][lL][tT][sSſ]|(?:[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sSſ]?[_.-]?[iI][dD]|[wW][iI][tT][hH][Cc][rR][eE][dD][eE][nN][tT][iI][aA][lL][sSſ])|(?:[bB][uU][cC][kKK][eE][tT]|[fF][oO][rR][eE][iI][gG][nN]|[hH][oO][tT]|[iI][dD][xX]|[nN][aA][tT][uU][rR][aA][lL]|[pP][rR][iI][mM][aA][rR][yY]|[pP][uU][bB](?:[lL][iI][cC])?|[sSſ][cC][hH][eE][mM][aA]|[sSſ][eE][qQ][uU][eE][nN][cC][eE])[_.-]?[kKK][eE][yY]|(?:[tT][uU][rR][kKK][eE][yY])|[kKK][eE][yY][_.-]?(?:[aA][lL][iI][aA][sSſ]|[bB][oO][aA][rR][dD]|[cC][oO][dD][eE]|[fF][rR][aA][mM][eE]|[iI][dD]|[lL][eE][nN][gG][tT][hH]|[mM][eE][sSſ][hH]|[nN][aA][mM][eE]|[pP][aA][iI][rR]|[pP][rR][eE][sSſ][sSſ](?:[eE][dD])?|[rR][iI][nN][gG]|[sSſ][eE][lL][eE][cC][tT][oO][rR]|[sSſ][iI][gG][nN][aA][tT][uU][rR][eE]|[sSſ][iI][zZ][eE]|[sSſ][tT][oO][nN][eE]|[sSſ][tT][oO][rR][eE][tT][yY][pP][eE]|[wW][oO][rR][dD]|[uU][pP]|[dD][oO][wW][nN]|[lL][eE][fF][tT]|[rR][iI][gG][hH][tT])|[kKK][eE][yY][_.-]?[vV][aA][uU][lL][tT][_.-]?(?:[iI][dD]|[nN][aA][mM][eE])|[kKK][eE][yY][Vv][aA][uU][lL][tT][Tt][oO][Ssſ][tT][oO][rR][eE][Ssſ][eE][cC][rR][eE][tT][sSſ]|[kKK][eE][yY](?:[sSſ][tT][oO][rR][eE]|[tT][aA][bB])[_.-]?(?:[fF][iI][lL][eE]|[pP][aA][tT][hH])|[iI][sSſ][sSſ][uU][eE][rR][kKK][eE][yY][hH][aA][sSſ][hH]|(?:[DdMm]onkey|[DM]ONKEY)|[kKK][eE][yY][iI][nN][gG]|(?:[sSſ][eE][cC][rR][eE][tT])[_.-]?(?:[lL][eE][nN][gG][tT][hH]|[nN][aA][mM][eE]|[sSſ][iI][zZ][eE])|[Uu][sSſ][eE][rR][Ssſ][eE][cC][rR][eE][tT][sSſ][Ii][dD]|(?:[cC][sSſ][rR][fF])[_.-]?[tT][oO][kKK][eE][nN]|(?:[iI][oO]\\.[jJ][sSſ][oO][nN][wW][eE][bB][tT][oO][kKK][eE][nN][ \\t]?:[ \\t]?[\\w-]+)|(?:[aA][pP][iI]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sSſ]|[tT][oO][kKK][eE][nN])[_.-]?(?:[eE][nN][dD][pP][oO][iI][nN][tT]|[uU][rR][iIlL])|[pP][uU][bB][lL][iI][cC][_.-]?[tT][oO][kKK][eE][nN]|(?:[kKK][eE][yY]|[tT][oO][kKK][eE][nN])[_.-]?[fF][iI][lL][eE]|(?:(?:[A-Z_]+=\\n[A-Z_]+=|[a-z_]+=\\n[a-z_]+=)(?:\\n|(?![\\s\\S])))|(?:(?:[A-Z.]+=\\n[A-Z.]+=|[a-z.]+=\\n[a-z.]+=)(?:\\n|(?![\\s\\S]))))"
          ],
          "stopwords": [
            "000000", "6fe4476ee5a1832882e326b506d14126", "_ec2_", "aaaaaa", "about", "abstract", "academy", "acces",
            "account", "act-", "act.", "act_", "action", "active", "actively", "activity",
            "adapter", "add-", "add-on", "add.", "add_", "addon", "addres", "admin",
            "adobe", "advanced", "adventure", "agent", "agile", "air-", "air.", "air_",
            "ajax", "akka", "alert", "alfred", "algorithm", "all-", "all.", "all_",
            "alloy", "alpha", "amazon", "amqp", "analysi", "analytic", "analyzer", "android",
            "angular", "angularj", "animate", "animation", "another", "ansible", "answer", "ant-",
            "ant.", "ant_", "any-", "any.", "any_", "apache", "app-", "app.",
            "app_", "apple", "arch", "archive", "archived", "arduino", "array", "art-",
            "art.", "art_", "article", "asp-", "asp.", "asp_", "asset", "async",
            "atom", "attention", "audio", "audit", "aura", "auth", "author", "authorize",
            "auto", "automated", "automatic", "awesome", "aws_", "azure", "back", "backbone",
            "backend", "backup", "bar-", "bar.", "bar_", "base", "based", "bash",
            "basic", "batch", "been", "beer", "behavior", "being", "benchmark", "best",
            "beta", "better", "big-", "big.", "big_", "binary", "binding", "bit-",
            "bit.", "bit_", "bitcoin", "block", "blog", "board", "book", "bookmark",
            "boost", "boot", "bootstrap", "bosh", "bot-", "bot.", "bot_", "bower",
            "box-", "box.", "box_", "boxen", "bracket", "branch", "bridge", "browser",
            "brunch", "buffer", "bug-", "bug.", "bug_", "build", "builder", "building",
            "buildout", "buildpack", "built", "bundle", "busines", "but-", "but.", "but_",
            "button", "cache", "caching", "cakephp", "calendar", "call", "camera", "campfire",
            "can-", "can.", "can_", "canva", "captcha", "capture", "card", "carousel",
            "case", "cassandra", "cat-", "cat.", "cat_", "category", "center", "cento",
            "challenge", "change", "changelog", "channel", "chart", "chat", "cheat", "check",
            "checker", "chef", "ches", "chinese", "chosen", "chrome", "ckeditor", "clas",
            "classe", "classic", "clean", "cli-", "cli.", "cli_", "client", "clojure",
            "clone", "closure", "cloud", "club", "cluster", "cms-", "cms_", "coco",
            "code", "coding", "coffee", "color", "combination", "combo", "command", "commander",
            "comment", "commit", "common", "community", "compas", "compiler", "complete", "component",
            "composer", "computer", "computing", "con-", "con.", "con_", "concept", "conf",
            "config", "connect", "connector", "console", "contact", "container", "contao", "content",
            "contest", "context", "control", "convert", "converter", "conway'", "cookbook", "cookie",
            "cool", "copy", "cordova", "core", "couchbase", "couchdb", "countdown", "counter",
            "course", "craft", "crawler", "create", "creating", "creator", "credential", "crm-",
            "crm.", "crm_", "cros", "crud", "csv-", "csv.", "csv_", "cube",
            "cucumber", "cuda", "current", "currently", "custom", "daemon", "dark", "dart",
            "dash", "dashboard", "data", "database", "date", "day-", "day.", "day_",
            "dead", "debian", "debug", "debugger", "deck", "define", "del-", "del.",
            "del_", "delete", "demo", "deploy", "design", "designer", "desktop", "detection",
            "detector", "dev-", "dev.", "dev_", "develop", "developer", "device", "devise",
            "diff", "digital", "directive", "directory", "discovery", "display", "django", "dns-",
            "dns_", "doc-", "doc.", "doc_", "docker", "docpad", "doctrine", "document",
            "doe-", "doe.", "doe_", "dojo", "dom-", "dom.", "dom_", "domain",
            "don't", "done", "dot-", "dot.", "dot_", "dotfile", "download", "draft",
            "drag", "drill", "drive", "driven", "driver", "drop", "dropbox", "drupal",
            "dsl-", "dsl.", "dsl_", "dynamic", "easy", "ecdsa", "eclipse", "edit",
            "editing", "edition", "editor", "element", "emac", "email", "embed", "embedded",
            "ember", "emitter", "emulator", "encoding", "endpoint", "engine", "english", "enhanced",
            "entity", "entry", "env_", "episode", "erlang", "error", "espresso", "event",
            "evented", "example", "exchange", "exercise", "experiment", "expire", "exploit", "explorer",
            "export", "exporter", "expres", "ext-", "ext.", "ext_", "extended", "extension",
            "external", "extra", "extractor", "fabric", "facebook", "factory", "fake", "fast",
            "feature", "feed", "fewfwef", "ffmpeg", "field", "file", "filter", "find",
            "finder", "firefox", "firmware", "first", "fish", "fix-", "fix_", "flash",
            "flask", "flat", "flex", "flexible", "flickr", "flow", "fluent", "fluentd",
            "fluid", "folder", "font", "force", "foreman", "fork", "form", "format",
            "formatter", "forum", "foundry", "framework", "free", "friend", "friendly", "front-end",
            "frontend", "ftp-", "ftp.", "ftp_", "fuel", "full", "fun-", "fun.",
            "fun_", "func", "future", "gaia", "gallery", "game", "gateway", "gem-",
            "gem.", "gem_", "gen-", "gen.", "gen_", "general", "generator", "generic",
            "genetic", "get-", "get.", "get_", "getenv", "getting", "ghost", "gist",
            "git-", "git.", "git_", "github", "gitignore", "gitlab", "glas", "gmail",
            "gnome", "gnu-", "gnu.", "gnu_", "goal", "golang", "gollum", "good",
            "google", "gpu-", "gpu.", "gpu_", "gradle", "grail", "graph", "graphic",
            "great", "grid", "groovy", "group", "grunt", "guard", "gui-", "gui.",
            "gui_", "guide", "guideline", "gulp", "gwt-", "gwt.", "gwt_", "hack",
            "hackathon", "hacker", "hacking", "hadoop", "haml", "handler", "hardware", "has-",
            "has_", "hash", "haskell", "have", "haxe", "hello", "help", "helper",
            "here", "hero", "heroku", "high", "hipchat", "history", "home", "homebrew",
            "homepage", "hook", "host", "hosting", "hot-", "hot.", "hot_", "house",
            "how-", "how.", "how_", "html", "http", "hub-", "hub.", "hub_",
            "hubot", "human", "icon", "ide-", "ide.", "ide_", "idea", "identity",
            "idiomatic", "image", "impact", "import", "important", "importer", "impres", "index",
            "infinite", "info", "injection", "inline", "input", "inside", "inspector", "instagram",
            "install", "installer", "instant", "intellij", "interface", "internet", "interview", "into",
            "intro", "ionic", "iphone", "ipython", "irc-", "irc_", "iso-", "iso.",
            "iso_", "issue", "jade", "jasmine", "java", "jbos", "jekyll", "jenkin",
            "jetbrains", "job-", "job.", "job_", "joomla", "jpa-", "jpa.", "jpa_",
            "jquery", "json", "just", "kafka", "karma", "kata", "kernel", "keyboard",
            "kindle", "kit-", "kit.", "kit_", "kitchen", "knife", "koan", "kohana",
            "lab-", "lab.", "lab_", "lambda", "lamp", "language", "laravel", "last",
            "latest", "latex", "launcher", "layer", "layout", "lazy", "ldap", "leaflet",
            "league", "learn", "learning", "led-", "led.", "led_", "leetcode", "les-",
            "les.", "les_", "level", "leveldb", "lib-", "lib.", "lib_", "librarie",
            "library", "license", "life", "liferay", "light", "lightbox", "like", "line",
            "link", "linked", "linkedin", "linux", "lisp", "list", "lite", "little",
            "load", "loader", "local", "location", "lock", "log-", "log.", "log_",
            "logger", "logging", "logic", "login", "logstash", "longer", "look", "love",
            "lua-", "lua.", "lua_", "mac-", "mac.", "mac_", "machine", "made",
            "magento", "magic", "mail", "make", "maker", "making", "man-", "man.",
            "man_", "manage", "manager", "manifest", "manual", "map-", "map.", "map_",
            "mapper", "mapping", "markdown", "markup", "master", "math", "matrix", "maven",
            "md5", "mean", "media", "mediawiki", "meetup", "memcached", "memory", "menu",
            "merchant", "message", "messaging", "meta", "metadata", "meteor", "method", "metric",
            "micro", "middleman", "migration", "minecraft", "miner", "mini", "minimal", "mirror",
            "mit-", "mit.", "mit_", "mobile", "mocha", "mock", "mod-", "mod.",
            "mod_", "mode", "model", "modern", "modular", "module", "modx", "money",
            "mongo", "mongodb", "mongoid", "mongoose", "monitor", "monkey", "more", "motion",
            "moved", "movie", "mozilla", "mqtt", "mule", "multi", "multiple", "music",
            "mustache", "mvc-", "mvc.", "mvc_", "mysql", "nagio", "name", "native",
            "need", "neo-", "neo.", "neo_", "nest", "nested", "net-", "net.",
            "net_", "nette", "network", "new-", "new.", "new_", "next", "nginx",
            "ninja", "nlp-", "nlp.", "nlp_", "node", "nodej", "nosql", "not-",
            "not.", "not_", "note", "notebook", "notepad", "notice", "notifier", "now-",
            "now.", "now_", "number", "oauth", "object", "objective", "obsolete", "ocaml",
            "octopres", "official", "old-", "old.", "old_", "onboard", "online", "only",
            "open", "opencv", "opengl", "openshift", "openwrt", "option", "oracle", "org-",
            "org.", "org_", "origin", "original", "orm-", "orm.", "orm_", "osx-",
            "osx_", "our-", "our.", "our_", "out-", "out.", "out_", "output",
            "over", "overview", "own-", "own.", "own_", "pack", "package", "packet",
            "page", "panel", "paper", "paperclip", "para", "parallax", "parallel", "parse",
            "parser", "parsing", "particle", "party", "password", "patch", "path", "pattern",
            "payment", "paypal", "pdf-", "pdf.", "pdf_", "pebble", "people", "perl",
            "personal", "phalcon", "phoenix", "phone", "phonegap", "photo", "php-", "php.",
            "php_", "physic", "picker", "pipeline", "platform", "play", "player", "please",
            "plu-", "plu.", "plu_", "plug-in", "plugin", "plupload", "png-", "png.",
            "png_", "poker", "polyfill", "polymer", "pool", "pop-", "pop.", "pop_",
            "popcorn", "popup", "port", "portable", "portal", "portfolio", "post", "power",
            "powered", "powerful", "prelude", "pretty", "preview", "principle", "print", "pro-",
            "pro.", "pro_", "problem", "proc", "product", "profile", "profiler", "program",
            "progres", "project", "protocol", "prototype", "provider", "proxy", "public", "pull",
            "puppet", "pure", "purpose", "push", "pusher", "pyramid", "python", "quality",
            "query", "queue", "quick", "rabbitmq", "rack", "radio", "rail", "railscast",
            "random", "range", "raspberry", "rdf-", "rdf.", "rdf_", "react", "reactive",
            "read", "reader", "readme", "ready", "real", "real-time", "reality", "realtime",
            "recipe", "recorder", "red-", "red.", "red_", "reddit", "redi", "redmine",
            "reference", "refinery", "refresh", "registry", "related", "release", "remote", "rendering",
            "repo", "report", "request", "require", "required", "requirej", "research", "resource",
            "response", "resque", "rest", "restful", "resume", "reveal", "reverse", "review",
            "riak", "rich", "right", "ring", "robot", "role", "room", "router",
            "routing", "rpc-", "rpc.", "rpc_", "rpg-", "rpg.", "rpg_", "rspec",
            "ruby-", "ruby.", "ruby_", "rule", "run-", "run.", "run_", "runner",
            "running", "runtime", "rust", "rvm-", "rvm.", "rvm_", "salt", "sample",
            "sandbox", "sas-", "sas.", "sas_", "sbt-", "sbt.", "sbt_", "scala",
            "scalable", "scanner", "schema", "scheme", "school", "science", "scraper", "scratch",
            "screen", "script", "scroll", "scs-", "scs.", "scs_", "sdk-", "sdk.",
            "sdk_", "sdl-", "sdl.", "sdl_", "search", "secure", "security", "see-",
            "see.", "see_", "seed", "select", "selector", "selenium", "semantic", "sencha",
            "send", "sentiment", "serie", "server", "service", "session", "set-", "set.",
            "set_", "setting", "setup", "sha1", "sha2", "sha256", "share", "shared",
            "sharing", "sheet", "shell", "shield", "shipping", "shop", "shopify", "shortener",
            "should", "show", "showcase", "side", "silex", "simple", "simulator", "single",
            "site", "skeleton", "sketch", "skin", "slack", "slide", "slider", "slim",
            "small", "smart", "smtp", "snake", "snapshot", "snippet", "soap", "social",
            "socket", "software", "solarized", "solr", "solution", "solver", "some", "soon",
            "source", "space", "spark", "spatial", "spec", "sphinx", "spine", "spotify",
            "spree", "spring", "sprite", "sql-", "sql.", "sql_", "sqlite", "ssh-",
            "ssh.", "ssh_", "stack", "staging", "standard", "stanford", "start", "started",
            "starter", "startup", "stat", "statamic", "state", "static", "statistic", "statsd",
            "statu", "steam", "step", "still", "stm-", "stm.", "stm_", "storage",
            "store", "storm", "story", "strategy", "stream", "streaming", "string", "stripe",
            "structure", "studio", "study", "stuff", "style", "sublime", "sugar", "suite",
            "summary", "super", "support", "supported", "svg-", "svg.", "svg_", "svn-",
            "svn.", "svn_", "swagger", "swift", "switch", "switcher", "symfony", "symphony",
            "sync", "synopsi", "syntax", "system", "tab-", "tab.", "tab_", "table",
            "tag-", "tag.", "tag_", "talk", "target", "task", "tcp-", "tcp.",
            "tcp_", "tdd-", "tdd.", "tdd_", "team", "tech", "template", "term",
            "terminal", "testing", "tetri", "text", "textmate", "theme", "theory", "three",
            "thrift", "time", "timeline", "timer", "tiny", "tinymce", "tip-", "tip.",
            "tip_", "title", "todo", "todomvc", "token", "tool", "toolbox", "toolkit",
            "top-", "top.", "top_", "tornado", "touch", "tower", "tracker", "tracking",
            "traffic", "training", "transfer", "translate", "transport", "tree", "trello", "try-",
            "try.", "try_", "tumblr", "tut-", "tut.", "tut_", "tutorial", "tweet",
            "twig", "twitter", "type", "typo", "ubuntu", "uiview", "ultimate", "under",
            "unit", "unity", "universal", "unix", "update", "updated", "upgrade", "upload",
            "uploader", "uri-", "uri.", "uri_", "url-", "url.", "url_", "usage",
            "usb-", "usb.", "usb_", "use-", "use.", "use_", "used", "useful",
            "user", "using", "util", "utilitie", "utility", "vagrant", "validator", "value",
            "variou", "varnish", "version", "via-", "via.", "via_", "video", "view",
            "viewer", "vim-", "vim.", "vim_", "vimrc", "virtual", "vision", "visual",
            "vpn", "want", "warning", "watch", "watcher", "wave", "way-", "way.",
            "way_", "weather", "web-", "web_", "webapp", "webgl", "webhook", "webkit",
            "webrtc", "website", "websocket", "welcome", "what", "what'", "when", "where",
            "which", "why-", "why.", "why_", "widget", "wifi", "wiki", "win-",
            "win.", "win_", "window", "wip-", "wip.", "wip_", "within", "without",
            "wizard", "word", "wordpres", "work", "worker", "workflow", "working", "workshop",
            "world", "wrapper", "write", "writer", "writing", "written", "www-", "www.",
            "www_", "xamarin", "xcode", "xml-", "xml.", "xml_", "xmpp", "xxxxxx",
            "yahoo", "yaml", "yandex", "yeoman", "yet-", "yet.", "yet_", "yii-",
            "yii.", "yii_", "youtube", "yui-", "yui.", "yui_", "zend", "zero",
            "zip-", "zip.", "zip_", "zsh-", "zsh.", "zsh_"
          ],
          "paths": []
        },
        {
          "condition": "OR",
          "regexTarget": "line",
          "regexes": [
            "--mount=type=secret,",
            "import[ \\t]+{[ \\t\\w,]+}[ \\t]+from[ \\t]+['\"][^'\"]+['\"]"
          ],
          "stopwords": [],
          "paths": []
        },
        {
          "condition": "AND",
          "regexTarget": "line",
          "regexes": [
            "LICENSE[^=]*=[\\t\\n\\f\\r ]*\"[^\"]+",
            "LIC_FILES_CHKSUM[^=]*=[\\t\\n\\f\\r ]*\"[^\"]+",
            "SRC[^=]*=[\\t\\n\\f\\r ]*\"[a-zA-Z0-9]+"
          ],
          "stopwords": [],
          "paths": [
            "\\.bb$",
            "\\.bbappend$",
            "\\.bbclass$",
            "\\.inc$"
          ]
        }
      ]
    },
    {
      "id": "openai-api-key",
      "description": "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
      "sourceRegex": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 3,
      "keywords": [
        "t3blbkfj"
      ],
      "allowlists": []
    },
    {
      "id": "anthropic-api-key",
      "description": "Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access.",
      "sourceRegex": "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 0,
      "keywords": [
        "sk-ant-api03"
      ],
      "allowlists": []
    },
    {
      "id": "anthropic-admin-api-key",
      "description": "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
      "sourceRegex": "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 0,
      "keywords": [
        "sk-ant-admin01"
      ],
      "allowlists": []
    },
    {
      "id": "gcp-api-key",
      "description": "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
      "sourceRegex": "\\b(AIza[\\w-]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(AIza[\\w-]{35})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 4,
      "keywords": [
        "aiza"
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [
            "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
            "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
            "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
            "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
            "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
            "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
            "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
            "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
            "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
            "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
            "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
            "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
            "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
            "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
            "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
            "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"
          ],
          "stopwords": [],
          "paths": []
        }
      ]
    },
    {
      "id": "github-pat",
      "description": "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
      "sourceRegex": "ghp_[0-9a-zA-Z]{36}",
      "regex": "ghp_[0-9a-zA-Z]{36}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "ghp_"
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [],
          "stopwords": [],
          "paths": [
            "(?:^|/)@octokit/auth-token/README\\.md$"
          ]
        }
      ]
    },
    {
      "id": "github-fine-grained-pat",
      "description": "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
      "sourceRegex": "github_pat_\\w{82}",
      "regex": "github_pat_\\w{82}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "github_pat_"
      ],
      "allowlists": []
    },
    {
      "id": "github-oauth",
      "description": "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
      "sourceRegex": "gho_[0-9a-zA-Z]{36}",
      "regex": "gho_[0-9a-zA-Z]{36}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "gho_"
      ],
      "allowlists": []
    },
    {
      "id": "github-app-token",
      "description": "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
      "sourceRegex": "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
      "regex": "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "ghu_",
        "ghs_"
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [],
          "stopwords": [],
          "paths": [
            "(?:^|/)@octokit/auth-token/README\\.md$"
          ]
        }
      ]
    },
    {
      "id": "github-refresh-token",
      "description": "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
      "sourceRegex": "ghr_[0-9a-zA-Z]{36}",
      "regex": "ghr_[0-9a-zA-Z]{36}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "ghr_"
      ],
      "allowlists": []
    },
    {
      "id": "aws-access-token",
      "description": "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
      "sourceRegex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
      "regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
      "secretGroup": 1,
      "entropy": 3,
      "keywords": [
        "a3t",
        "akia",
        "asia",
        "abia",
        "acca"
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [
            "[^\\n]+EXAMPLE(?![\\s\\S])"
          ],
          "stopwords": [],
          "paths": []
        }
      ]
    },
    {
      "id": "private-key",
      "description": "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
      "sourceRegex": "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----",
      "regex": "-----[Bb][Ee][Gg][Ii][Nn][ AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9_-]{0,100}[Pp][Rr][Ii][Vv][Aa][Tt][Ee] [KkK][Ee][Yy](?: [Bb][Ll][Oo][Cc][KkK])?-----[\\s\\S-]{64,}?[KkK][Ee][Yy](?: [Bb][Ll][Oo][Cc][KkK])?-----",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "-----begin"
      ],
      "allowlists": []
    },
    {
      "id": "jwt",
      "description": "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
      "sourceRegex": "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 3,
      "keywords": [
        "ey"
      ],
      "allowlists": []
    },
    {
      "id": "curl-auth-header",
      "description": "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.",
      "sourceRegex": "\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?i)(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\"|'(?i)(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|\\z)",
      "regex": "\\bcurl\\b(?:[^\\n]*?|[^\\n]*?(?:[\\r\\n]{1,2}[^\\n]*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \\t]{0,5}(?:[Bb][aA][sSſ][iI][cC][ \\t]([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9+/]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kKK][eE][nN])[ \\t]([A-Za-z0-9_ſK=~@.+/-]{8,})|([A-Za-z0-9_ſK=~@.+/-]{8,}))|(?:(?:[Xx]-(?:[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ]+-)?)?(?:[Aa][pP][iI]-?)?(?:[KkK][eE][yY]|[Tt][oO][kKK][eE][nN])):[ \\t]{0,5}([A-Za-z0-9_ſK=~@.+/-]{8,}))\"|'(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \\t]{0,5}(?:[Bb][aA][sSſ][iI][cC][ \\t]([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9+/]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kKK][eE][nN])[ \\t]([A-Za-z0-9_ſK=~@.+/-]{8,})|([A-Za-z0-9_ſK=~@.+/-]{8,}))|(?:(?:[Xx]-(?:[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ]+-)?)?(?:[Aa][pP][iI]-?)?(?:[KkK][eE][yY]|[Tt][oO][kKK][eE][nN])):[ \\t]{0,5}([A-Za-z0-9_ſK=~@.+/-]{8,}))')(?:\\B|[\\t\\n\\f\\r ]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2.75,
      "keywords": [
        "curl"
      ],
      "allowlists": [],
      "command": {
        "start": "\\bcurl\\b",
        "prefix": "\\bcurl\\b(?:[^\\n]*?|[^\\n]*?(?:[\\r\\n]{1,2}[^\\n]*?){1,5})",
        "lineBreakGroups": 5
      }
    },
    {
      "id": "curl-auth-user",
      "description": "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.",
      "sourceRegex": "\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.-]+)))(?:\\s|\\z)",
      "regex": "\\bcurl\\b(?:[^\\n]*|[^\\n]*(?:[\\r\\n]{1,2}[^\\n]*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.-]+)))(?:[\\t\\n\\f\\r ]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "curl"
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [
            "[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
            "['\"]?<[^>]+>['\"]?:['\"]?<[^>]+>|<[^:]+:[^>]+>['\"]?",
            "[^:]+:\\[[^\\]]+]",
            "['\"]?[^:]+['\"]?:['\"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['\"]?",
            "\\$\\([^)]+\\):\\$\\([^)]+\\)",
            "['\"]?\\$?{{[^}]+}}['\"]?:['\"]?\\$?{{[^}]+}}['\"]?"
          ],
          "stopwords": [],
          "paths": []
        }
      ],
      "command": {
        "start": "\\bcurl\\b",
        "prefix": "\\bcurl\\b(?:[^\\n]*|[^\\n]*(?:[\\r\\n]{1,2}[^\\n]*){1,5})",
        "lineBreakGroups": 5
      }
    },
    {
      "id": "npm-access-token",
      "description": "Uncovered an npm access token, potentially compromising package management and code repository access.",
      "sourceRegex": "(?i)\\b(npm_[a-z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([nN][pP][mM]_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{36})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 2,
      "keywords": [
        "npm_"
      ],
      "allowlists": []
    },
    {
      "id": "slack-app-token",
      "description": "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.",
      "sourceRegex": "(?i)xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+",
      "regex": "[xX][aA][pP][pP]-\\d-[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9]+-\\d+-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]+",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xapp"
      ],
      "allowlists": []
    },
    {
      "id": "slack-bot-token",
      "description": "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.",
      "sourceRegex": "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
      "regex": "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "xoxb"
      ],
      "allowlists": []
    },
    {
      "id": "slack-config-access-token",
      "description": "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.",
      "sourceRegex": "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}",
      "regex": "[xX][oO][xX][eE][^\\n][xX][oO][xX][bBpP]-\\d-[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9]{163,166}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xoxe.xoxb-",
        "xoxe.xoxp-"
      ],
      "allowlists": []
    },
    {
      "id": "slack-config-refresh-token",
      "description": "Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings.",
      "sourceRegex": "(?i)xoxe-\\d-[A-Z0-9]{146}",
      "regex": "[xX][oO][xX][eE]-\\d-[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9]{146}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xoxe-"
      ],
      "allowlists": []
    },
    {
      "id": "slack-legacy-bot-token",
      "description": "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.",
      "sourceRegex": "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
      "regex": "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xoxb"
      ],
      "allowlists": []
    },
    {
      "id": "slack-legacy-token",
      "description": "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.",
      "sourceRegex": "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
      "regex": "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xoxo",
        "xoxs"
      ],
      "allowlists": []
    },
    {
      "id": "slack-legacy-workspace-token",
      "description": "Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.",
      "sourceRegex": "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
      "regex": "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xoxa",
        "xoxr"
      ],
      "allowlists": []
    },
    {
      "id": "slack-user-token",
      "description": "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.",
      "sourceRegex": "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
      "regex": "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xoxp-",
        "xoxe-"
      ],
      "allowlists": []
    },
    {
      "id": "slack-webhook-url",
      "description": "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.",
      "sourceRegex": "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
      "regex": "(?:https?://)?hooks[^\\n]slack[^\\n]com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "hooks.slack.com"
      ],
      "allowlists": []
    },
    {
      "id": "stripe-access-token",
      "description": "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.",
      "sourceRegex": "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 1,
      "entropy": 2,
      "keywords": [
        "sk_test",
        "sk_live",
        "sk_prod",
        "rk_test",
        "rk_live",
        "rk_prod"
      ],
      "allowlists": []
    },
    {
      "id": "1password-secret-key",
      "description": "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.",
      "sourceRegex": "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      "regex": "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      "secretGroup": 0,
      "entropy": 3.8,
      "keywords": [
        "a3-"
      ],
      "allowlists": []
    },
    {
      "id": "1password-service-account-token",
      "description": "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.",
      "sourceRegex": "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
      "regex": "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "ops_"
      ],
      "allowlists": []
    },
    {
      "id": "adafruit-api-key",
      "description": "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][dD][aA][fF][rR][uU][iI][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_-]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "adafruit"
      ],
      "allowlists": []
    },
    {
      "id": "adobe-client-id",
      "description": "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][dD][oO][bB][eE])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "adobe"
      ],
      "allowlists": []
    },
    {
      "id": "adobe-client-secret",
      "description": "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
      "sourceRegex": "\\b(p8e-(?i)[a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(p8e-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "p8e-"
      ],
      "allowlists": []
    },
    {
      "id": "age-secret-key",
      "description": "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.",
      "sourceRegex": "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
      "regex": "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "age-secret-key-1"
      ],
      "allowlists": []
    },
    {
      "id": "airtable-api-key",
      "description": "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{17})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][iI][rR][tT][aA][bB][lL][eE])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{17})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "airtable"
      ],
      "allowlists": []
    },
    {
      "id": "airtable-personnal-access-token",
      "description": "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
      "sourceRegex": "\\b(pat[[:alnum:]]{14}\\.[a-f0-9]{64})\\b",
      "regex": "\\b(pat[0-9A-Za-z]{14}\\.[a-f0-9]{64})\\b",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "airtable"
      ],
      "allowlists": []
    },
    {
      "id": "algolia-api-key",
      "description": "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][lL][gG][oO][lL][iI][aA])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "algolia"
      ],
      "allowlists": []
    },
    {
      "id": "alibaba-access-key-id",
      "description": "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
      "sourceRegex": "\\b(LTAI(?i)[a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(LTAI[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{20})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "ltai"
      ],
      "allowlists": []
    },
    {
      "id": "alibaba-secret-key",
      "description": "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][lL][iI][bB][aA][bB][aA])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{30})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "alibaba"
      ],
      "allowlists": []
    },
    {
      "id": "artifactory-api-key",
      "description": "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
      "sourceRegex": "\\bAKCp[A-Za-z0-9]{69}\\b",
      "regex": "\\bAKCp[A-Za-z0-9]{69}\\b",
      "secretGroup": 0,
      "entropy": 4.5,
      "keywords": [
        "akcp"
      ],
      "allowlists": []
    },
    {
      "id": "artifactory-reference-token",
      "description": "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
      "sourceRegex": "\\bcmVmd[A-Za-z0-9]{59}\\b",
      "regex": "\\bcmVmd[A-Za-z0-9]{59}\\b",
      "secretGroup": 0,
      "entropy": 4.5,
      "keywords": [
        "cmvmd"
      ],
      "allowlists": []
    },
    {
      "id": "asana-client-id",
      "description": "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][sSſ][aA][nN][aA])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "asana"
      ],
      "allowlists": []
    },
    {
      "id": "asana-client-secret",
      "description": "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[aA][sSſ][aA][nN][aA])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "asana"
      ],
      "allowlists": []
    },
    {
      "id": "atlassian-api-token",
      "description": "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\\x60'\"\\s;]|\\\\[nr]|$)|\\b(ATATT3[A-Za-z0-9_\\-=]{186})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:(?:ATLASSIAN|[Aa]tlassian)|(?:CONFLUENCE|[Cc]onfluence)|(?:JIRA|[Jj]ira))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{20}[aAbBcCdDeEfF0-9]{4})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))|\\b([Aa][Tt][Aa][Tt][Tt]3[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZzaAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_\\x2d=]{186})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "atlassian",
        "confluence",
        "jira",
        "atatt3"
      ],
      "allowlists": []
    },
    {
      "id": "authress-service-client-access-key",
      "description": "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.",
      "sourceRegex": "\\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\\.[a-z0-9]{4,6}\\.(?-i:acc)[_-][a-z0-9-]{10,32}\\.[a-z0-9+/_=-]{30,120})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b((?:sc|ext|scauth|authress)_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{5,30}\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{4,6}\\.(?:acc)[_-][aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9-]{10,32}\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9+/_=-]{30,120})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "sc_",
        "ext_",
        "scauth_",
        "authress_"
      ],
      "allowlists": []
    },
    {
      "id": "aws-amazon-bedrock-api-key-long-lived",
      "description": "Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
      "sourceRegex": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "absk"
      ],
      "allowlists": []
    },
    {
      "id": "aws-amazon-bedrock-api-key-short-lived",
      "description": "Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
      "sourceRegex": "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
      "regex": "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "bedrock-api-key-"
      ],
      "allowlists": []
    },
    {
      "id": "azure-ad-client-secret",
      "description": "Azure AD Client Secret",
      "sourceRegex": "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'\"\\x60\\s<),])",
      "regex": "(?:^|[\\\\'\"\\x60\\t\\n\\f\\r >=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:(?![\\s\\S])|[\\\\'\"\\x60\\t\\n\\f\\r <),])",
      "secretGroup": 0,
      "reuseBoundary": true,
      "entropy": 3,
      "keywords": [
        "q~"
      ],
      "allowlists": []
    },
    {
      "id": "beamer-api-token",
      "description": "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([bB]_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{44})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "beamer"
      ],
      "allowlists": []
    },
    {
      "id": "bitbucket-client-id",
      "description": "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[bB][iI][tT][bB][uU][cC][kKK][eE][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "bitbucket"
      ],
      "allowlists": []
    },
    {
      "id": "bitbucket-client-secret",
      "description": "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[bB][iI][tT][bB][uU][cC][kKK][eE][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "bitbucket"
      ],
      "allowlists": []
    },
    {
      "id": "bittrex-access-key",
      "description": "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "bittrex"
      ],
      "allowlists": []
    },
    {
      "id": "bittrex-secret-key",
      "description": "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "bittrex"
      ],
      "allowlists": []
    },
    {
      "id": "cisco-meraki-api-key",
      "description": "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.",
      "sourceRegex": "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[\\w.-]{0,50}?(?:[A-Za-z0-9_ſK.-]{0,50}?(?:(?:[Mm]eraki|MERAKI))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9a-f]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "meraki"
      ],
      "allowlists": []
    },
    {
      "id": "clickhouse-cloud-api-secret-key",
      "description": "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.",
      "sourceRegex": "\\b(4b1d[A-Za-z0-9]{38})\\b",
      "regex": "\\b(4b1d[A-Za-z0-9]{38})\\b",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "4b1d"
      ],
      "allowlists": []
    },
    {
      "id": "clojars-api-token",
      "description": "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
      "sourceRegex": "(?i)CLOJARS_[a-z0-9]{60}",
      "regex": "[Cc][Ll][Oo][Jj][Aa][Rr][Ssſ]_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{60}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "clojars_"
      ],
      "allowlists": []
    },
    {
      "id": "cloudflare-api-key",
      "description": "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_-]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "cloudflare"
      ],
      "allowlists": []
    },
    {
      "id": "cloudflare-global-api-key",
      "description": "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{37})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "cloudflare"
      ],
      "allowlists": []
    },
    {
      "id": "cloudflare-origin-ca-key",
      "description": "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.",
      "sourceRegex": "\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "cloudflare",
        "v1.0-"
      ],
      "allowlists": []
    },
    {
      "id": "codecov-access-token",
      "description": "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][oO][dD][eE][cC][oO][vV])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "codecov"
      ],
      "allowlists": []
    },
    {
      "id": "cohere-api-token",
      "description": "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
      "sourceRegex": "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[\\w.-]{0,50}?(?:[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][oO][hH][eE][rR][eE]|[Cc][Oo]_[Aa][Pp][Ii]_[KkK][Ee][Yy])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "cohere",
        "co_api_key"
      ],
      "allowlists": []
    },
    {
      "id": "coinbase-access-token",
      "description": "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][oO][iI][nN][bB][aA][sSſ][eE])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_-]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "coinbase"
      ],
      "allowlists": []
    },
    {
      "id": "confluent-access-token",
      "description": "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "confluent"
      ],
      "allowlists": []
    },
    {
      "id": "confluent-secret-key",
      "description": "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "confluent"
      ],
      "allowlists": []
    },
    {
      "id": "contentful-delivery-api-token",
      "description": "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[cC][oO][nN][tT][eE][nN][tT][fF][uU][lL])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{43})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "contentful"
      ],
      "allowlists": []
    },
    {
      "id": "databricks-api-token",
      "description": "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
      "sourceRegex": "\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "dapi"
      ],
      "allowlists": []
    },
    {
      "id": "datadog-access-token",
      "description": "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][aA][tT][aA][dD][oO][gG])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "datadog"
      ],
      "allowlists": []
    },
    {
      "id": "defined-networking-api-token",
      "description": "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][nN][kKK][eE][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([dD][nN][kKK][eE][yY]-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{26}-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{52})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "dnkey"
      ],
      "allowlists": []
    },
    {
      "id": "digitalocean-access-token",
      "description": "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
      "sourceRegex": "\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "doo_v1_"
      ],
      "allowlists": []
    },
    {
      "id": "digitalocean-pat",
      "description": "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
      "sourceRegex": "\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "dop_v1_"
      ],
      "allowlists": []
    },
    {
      "id": "digitalocean-refresh-token",
      "description": "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
      "sourceRegex": "(?i)\\b(dor_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([dD][oO][rR]_[vV]1_[aAbBcCdDeEfF0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "dor_v1_"
      ],
      "allowlists": []
    },
    {
      "id": "discord-api-token",
      "description": "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][iI][sSſ][cC][oO][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "discord"
      ],
      "allowlists": []
    },
    {
      "id": "discord-client-id",
      "description": "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{18})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][iI][sSſ][cC][oO][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9]{18})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "discord"
      ],
      "allowlists": []
    },
    {
      "id": "discord-client-secret",
      "description": "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][iI][sSſ][cC][oO][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "discord"
      ],
      "allowlists": []
    },
    {
      "id": "doppler-api-token",
      "description": "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
      "sourceRegex": "dp\\.pt\\.(?i)[a-z0-9]{43}",
      "regex": "dp\\.pt\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{43}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "dp.pt."
      ],
      "allowlists": []
    },
    {
      "id": "droneci-access-token",
      "description": "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][rR][oO][nN][eE][cC][iI])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "droneci"
      ],
      "allowlists": []
    },
    {
      "id": "dropbox-api-token",
      "description": "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{15})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{15})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "dropbox"
      ],
      "allowlists": []
    },
    {
      "id": "dropbox-long-lived-api-token",
      "description": "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{11}([Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa])[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\x2d_=]{43})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "dropbox"
      ],
      "allowlists": []
    },
    {
      "id": "dropbox-short-lived-api-token",
      "description": "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([sSſ][lL]\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\x2d=_]{135})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "dropbox"
      ],
      "allowlists": []
    },
    {
      "id": "duffel-api-token",
      "description": "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
      "sourceRegex": "duffel_(?:test|live)_(?i)[a-z0-9_\\-=]{43}",
      "regex": "duffel_(?:test|live)_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_\\x2d=]{43}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "duffel_"
      ],
      "allowlists": []
    },
    {
      "id": "dynatrace-api-token",
      "description": "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
      "sourceRegex": "dt0c01\\.(?i)[a-z0-9]{24}\\.[a-z0-9]{64}",
      "regex": "dt0c01\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{24}\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{64}",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "dt0c01."
      ],
      "allowlists": []
    },
    {
      "id": "easypost-api-token",
      "description": "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
      "sourceRegex": "\\bEZAK(?i)[a-z0-9]{54}\\b",
      "regex": "\\bEZAK[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{54}\\b",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "ezak"
      ],
      "allowlists": []
    },
    {
      "id": "easypost-test-api-token",
      "description": "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
      "sourceRegex": "\\bEZTK(?i)[a-z0-9]{54}\\b",
      "regex": "\\bEZTK[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{54}\\b",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "eztk"
      ],
      "allowlists": []
    },
    {
      "id": "etsy-access-token",
      "description": "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:(?:ETSY|[Ee]tsy))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{24})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "etsy"
      ],
      "allowlists": []
    },
    {
      "id": "facebook-access-token",
      "description": "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
      "sourceRegex": "(?i)\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(\\d{15,16}(\\||%)[0-9aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ\\x2d_]{27,40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "facebook"
      ],
      "allowlists": []
    },
    {
      "id": "facebook-page-access-token",
      "description": "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
      "sourceRegex": "\\b(EAA[MC](?i)[a-z0-9]{100,})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(EAA[MC][aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{100,})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "eaam",
        "eaac"
      ],
      "allowlists": []
    },
    {
      "id": "facebook-secret",
      "description": "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][aA][cC][eE][bB][oO][oO][kKK])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "facebook"
      ],
      "allowlists": []
    },
    {
      "id": "fastly-api-token",
      "description": "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][aA][sSſ][tT][lL][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "fastly"
      ],
      "allowlists": []
    },
    {
      "id": "finicity-api-token",
      "description": "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "finicity"
      ],
      "allowlists": []
    },
    {
      "id": "finicity-client-secret",
      "description": "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{20})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "finicity"
      ],
      "allowlists": []
    },
    {
      "id": "finnhub-access-token",
      "description": "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][iI][nN][nN][hH][uU][bB])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{20})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "finnhub"
      ],
      "allowlists": []
    },
    {
      "id": "flickr-access-token",
      "description": "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][lL][iI][cC][kKK][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "flickr"
      ],
      "allowlists": []
    },
    {
      "id": "flutterwave-encryption-key",
      "description": "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
      "sourceRegex": "FLWSECK_TEST-(?i)[a-h0-9]{12}",
      "regex": "FLWSECK_TEST-[aAbBcCdDeEfFgGhH0-9]{12}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "flwseck_test"
      ],
      "allowlists": []
    },
    {
      "id": "flutterwave-public-key",
      "description": "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.",
      "sourceRegex": "FLWPUBK_TEST-(?i)[a-h0-9]{32}-X",
      "regex": "FLWPUBK_TEST-[aAbBcCdDeEfFgGhH0-9]{32}-[Xx]",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "flwpubk_test"
      ],
      "allowlists": []
    },
    {
      "id": "flutterwave-secret-key",
      "description": "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
      "sourceRegex": "FLWSECK_TEST-(?i)[a-h0-9]{32}-X",
      "regex": "FLWSECK_TEST-[aAbBcCdDeEfFgGhH0-9]{32}-[Xx]",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "flwseck_test"
      ],
      "allowlists": []
    },
    {
      "id": "flyio-access-token",
      "description": "Uncovered a Fly.io API key",
      "sourceRegex": "\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "fo1_",
        "fm1",
        "fm2_"
      ],
      "allowlists": []
    },
    {
      "id": "frameio-api-token",
      "description": "Found a Frame.io API token, potentially compromising video collaboration and project management.",
      "sourceRegex": "fio-u-(?i)[a-z0-9\\-_=]{64}",
      "regex": "fio-u-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\x2d_=]{64}",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "fio-u-"
      ],
      "allowlists": []
    },
    {
      "id": "freshbooks-access-token",
      "description": "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[fF][rR][eE][sSſ][hH][bB][oO][oO][kKK][sSſ])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "freshbooks"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-cicd-job-token",
      "description": "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
      "sourceRegex": "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
      "regex": "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glcbt-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-deploy-token",
      "description": "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
      "sourceRegex": "gldt-[0-9a-zA-Z_\\-]{20}",
      "regex": "gldt-[0-9a-zA-Z_\\x2d]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "gldt-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-feature-flag-client-token",
      "description": "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
      "sourceRegex": "glffct-[0-9a-zA-Z_\\-]{20}",
      "regex": "glffct-[0-9a-zA-Z_\\x2d]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glffct-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-feed-token",
      "description": "Identified a GitLab feed token, risking exposure of user data.",
      "sourceRegex": "glft-[0-9a-zA-Z_\\-]{20}",
      "regex": "glft-[0-9a-zA-Z_\\x2d]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glft-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-incoming-mail-token",
      "description": "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
      "sourceRegex": "glimt-[0-9a-zA-Z_\\-]{25}",
      "regex": "glimt-[0-9a-zA-Z_\\x2d]{25}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glimt-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-kubernetes-agent-token",
      "description": "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
      "sourceRegex": "glagent-[0-9a-zA-Z_\\-]{50}",
      "regex": "glagent-[0-9a-zA-Z_\\x2d]{50}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glagent-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-oauth-app-secret",
      "description": "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
      "sourceRegex": "gloas-[0-9a-zA-Z_\\-]{64}",
      "regex": "gloas-[0-9a-zA-Z_\\x2d]{64}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "gloas-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-pat",
      "description": "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
      "sourceRegex": "glpat-[\\w-]{20}",
      "regex": "glpat-[\\w-]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glpat-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-pat-routable",
      "description": "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.",
      "sourceRegex": "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "regex": "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "glpat-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-ptt",
      "description": "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
      "sourceRegex": "glptt-[0-9a-f]{40}",
      "regex": "glptt-[0-9a-f]{40}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glptt-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-rrt",
      "description": "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
      "sourceRegex": "GR1348941[\\w-]{20}",
      "regex": "GR1348941[\\w-]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "gr1348941"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-runner-authentication-token",
      "description": "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
      "sourceRegex": "glrt-[0-9a-zA-Z_\\-]{20}",
      "regex": "glrt-[0-9a-zA-Z_\\x2d]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glrt-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-runner-authentication-token-routable",
      "description": "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.",
      "sourceRegex": "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "regex": "\\bglrt-t\\d_[0-9a-zA-Z_\\x2d]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "glrt-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-scim-token",
      "description": "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
      "sourceRegex": "glsoat-[0-9a-zA-Z_\\-]{20}",
      "regex": "glsoat-[0-9a-zA-Z_\\x2d]{20}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glsoat-"
      ],
      "allowlists": []
    },
    {
      "id": "gitlab-session-cookie",
      "description": "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
      "sourceRegex": "_gitlab_session=[0-9a-z]{32}",
      "regex": "_gitlab_session=[0-9a-z]{32}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "_gitlab_session="
      ],
      "allowlists": []
    },
    {
      "id": "gitter-access-token",
      "description": "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[gG][iI][tT][tT][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_-]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "gitter"
      ],
      "allowlists": []
    },
    {
      "id": "gocardless-api-token",
      "description": "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(live_(?i)[a-z0-9\\-_=]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[gG][oO][cC][aA][rR][dD][lL][eE][sSſ][sSſ])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([lL][iI][vV][eE]_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\x2d_=]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "live_",
        "gocardless"
      ],
      "allowlists": []
    },
    {
      "id": "grafana-api-key",
      "description": "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
      "sourceRegex": "(?i)\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([eE][yY][Jj][rR][Ii][jJ][oO][iI][AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZzaAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{70,400}={0,3})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "eyjrijoi"
      ],
      "allowlists": []
    },
    {
      "id": "grafana-cloud-api-token",
      "description": "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.",
      "sourceRegex": "(?i)\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([gG][lL][cC]_[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZzaAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9+/]{32,400}={0,3})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glc_"
      ],
      "allowlists": []
    },
    {
      "id": "grafana-service-account-token",
      "description": "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
      "sourceRegex": "(?i)\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([gG][lL][sSſ][aA]_[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZzaAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{32}_[AaBbCcDdEeFfaAbBcCdDeEfF0-9]{8})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "glsa_"
      ],
      "allowlists": []
    },
    {
      "id": "harness-api-key",
      "description": "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
      "sourceRegex": "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
      "regex": "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "pat.",
        "sat."
      ],
      "allowlists": []
    },
    {
      "id": "hashicorp-tf-api-token",
      "description": "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
      "sourceRegex": "(?i)[a-z0-9]{14}\\.(?-i:atlasv1)\\.[a-z0-9\\-_=]{60,70}",
      "regex": "[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{14}\\.(?:atlasv1)\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\x2d_=]{60,70}",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "atlasv1"
      ],
      "allowlists": []
    },
    {
      "id": "heroku-api-key",
      "description": "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[hH][eE][rR][oO][kKK][uU])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "heroku"
      ],
      "allowlists": []
    },
    {
      "id": "heroku-api-key-v2",
      "description": "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
      "sourceRegex": "\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "hrku-aa"
      ],
      "allowlists": []
    },
    {
      "id": "hubspot-api-key",
      "description": "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[hH][uU][bB][sSſ][pP][oO][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9AaBbCcDdEeFf]{8}-[0-9AaBbCcDdEeFf]{4}-[0-9AaBbCcDdEeFf]{4}-[0-9AaBbCcDdEeFf]{4}-[0-9AaBbCcDdEeFf]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "hubspot"
      ],
      "allowlists": []
    },
    {
      "id": "huggingface-access-token",
      "description": "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
      "sourceRegex": "\\b(hf_(?i:[a-z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(hf_(?:[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ]{34}))(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "hf_"
      ],
      "allowlists": []
    },
    {
      "id": "huggingface-organization-api-token",
      "description": "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
      "sourceRegex": "\\b(api_org_(?i:[a-z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(api_org_(?:[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ]{34}))(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "api_org_"
      ],
      "allowlists": []
    },
    {
      "id": "infracost-api-token",
      "description": "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",
      "sourceRegex": "\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "ico-"
      ],
      "allowlists": []
    },
    {
      "id": "intercom-api-key",
      "description": "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[iI][nN][tT][eE][rR][cC][oO][mM])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{60})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "intercom"
      ],
      "allowlists": []
    },
    {
      "id": "intra42-client-secret",
      "description": "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.",
      "sourceRegex": "\\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(s-s4t2(?:ud|af)-[aAbBcCdDeEfF0123456789]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "intra",
        "s-s4t2ud-",
        "s-s4t2af-"
      ],
      "allowlists": []
    },
    {
      "id": "jfrog-api-key",
      "description": "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{73})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[jJ][fF][rR][oO][gG]|[aA][rR][tT][iI][fF][aA][cC][tT][oO][rR][yY]|[bB][iI][nN][tT][rR][aA][yY]|[xX][rR][aA][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{73})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "jfrog",
        "artifactory",
        "bintray",
        "xray"
      ],
      "allowlists": []
    },
    {
      "id": "jfrog-identity-token",
      "description": "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[jJ][fF][rR][oO][gG]|[aA][rR][tT][iI][fF][aA][cC][tT][oO][rR][yY]|[bB][iI][nN][tT][rR][aA][yY]|[xX][rR][aA][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "jfrog",
        "artifactory",
        "bintray",
        "xray"
      ],
      "allowlists": []
    },
    {
      "id": "jwt-base64",
      "description": "Detected a Base64-encoded JSON Web Token, posing a risk of exposing encoded authentication and data exchange information.",
      "sourceRegex": "\\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
      "regex": "\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\x2d\\r\\n]{40,}={0,2}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "zxlk"
      ],
      "allowlists": [],
      "maskGroup": 0
    },
    {
      "id": "kraken-access-token",
      "description": "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:kraken)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9\\/=_\\+\\-]{80,90})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[kKK][rR][aA][kKK][eE][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\/=_\\+\\x2d]{80,90})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "kraken"
      ],
      "allowlists": []
    },
    {
      "id": "kucoin-access-token",
      "description": "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[kKK][uU][cC][oO][iI][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{24})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "kucoin"
      ],
      "allowlists": []
    },
    {
      "id": "kucoin-secret-key",
      "description": "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[kKK][uU][cC][oO][iI][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "kucoin"
      ],
      "allowlists": []
    },
    {
      "id": "launchdarkly-access-token",
      "description": "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][aA][uU][nN][cC][hH][dD][aA][rR][kKK][lL][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "launchdarkly"
      ],
      "allowlists": []
    },
    {
      "id": "linear-api-key",
      "description": "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
      "sourceRegex": "lin_api_(?i)[a-z0-9]{40}",
      "regex": "lin_api_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{40}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "lin_api_"
      ],
      "allowlists": []
    },
    {
      "id": "linear-client-secret",
      "description": "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][iI][nN][eE][aA][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "linear"
      ],
      "allowlists": []
    },
    {
      "id": "linkedin-client-id",
      "description": "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{14})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][iI][nN][kKK][eE][dD][_-]?[iI][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{14})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "linkedin",
        "linked_in",
        "linked-in"
      ],
      "allowlists": []
    },
    {
      "id": "linkedin-client-secret",
      "description": "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][iI][nN][kKK][eE][dD][_-]?[iI][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "linkedin",
        "linked_in",
        "linked-in"
      ],
      "allowlists": []
    },
    {
      "id": "lob-api-key",
      "description": "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][oO][bB])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}(([lL][iI][vV][eE]|[tT][eE][sSſ][tT])_[aAbBcCdDeEfF0-9]{35})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "test_",
        "live_"
      ],
      "allowlists": []
    },
    {
      "id": "lob-pub-api-key",
      "description": "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][oO][bB])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}(([tT][eE][sSſ][tT]|[lL][iI][vV][eE])_[pP][uU][bB]_[aAbBcCdDeEfF0-9]{31})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "test_pub",
        "live_pub",
        "_pub"
      ],
      "allowlists": []
    },
    {
      "id": "looker-client-id",
      "description": "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][oO][oO][kKK][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{20})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "looker"
      ],
      "allowlists": []
    },
    {
      "id": "looker-client-secret",
      "description": "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[lL][oO][oO][kKK][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{24})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "looker"
      ],
      "allowlists": []
    },
    {
      "id": "mailchimp-api-key",
      "description": "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[Mm][aA][iI][lL][cC][hH][iI][mM][pP][Ssſ][Dd][KkK][^\\n][iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{32}-[uU][sSſ]\\d\\d)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "mailchimp"
      ],
      "allowlists": []
    },
    {
      "id": "mailgun-private-api-token",
      "description": "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([kKK][eE][yY]-[aAbBcCdDeEfF0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "mailgun"
      ],
      "allowlists": []
    },
    {
      "id": "mailgun-pub-key",
      "description": "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([pP][uU][bB][kKK][eE][yY]-[aAbBcCdDeEfF0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "mailgun"
      ],
      "allowlists": []
    },
    {
      "id": "mailgun-signing-key",
      "description": "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhH0-9]{32}-[aAbBcCdDeEfFgGhH0-9]{8}-[aAbBcCdDeEfFgGhH0-9]{8})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "mailgun"
      ],
      "allowlists": []
    },
    {
      "id": "mapbox-api-token",
      "description": "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][aA][pP][bB][oO][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([pP][kKK]\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{60}\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{22})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "mapbox"
      ],
      "allowlists": []
    },
    {
      "id": "mattermost-access-token",
      "description": "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][aA][tT][tT][eE][rR][mM][oO][sSſ][tT])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{26})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "mattermost"
      ],
      "allowlists": []
    },
    {
      "id": "maxmind-license-key",
      "description": "Discovered a potential MaxMind license key.",
      "sourceRegex": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "_mmk"
      ],
      "allowlists": []
    },
    {
      "id": "messagebird-api-token",
      "description": "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][eE][sSſ][sSſ][aA][gG][eE][_-]?[bB][iI][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{25})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "messagebird",
        "message-bird",
        "message_bird"
      ],
      "allowlists": []
    },
    {
      "id": "messagebird-client-id",
      "description": "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[mM][eE][sSſ][sSſ][aA][gG][eE][_-]?[bB][iI][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "messagebird",
        "message-bird",
        "message_bird"
      ],
      "allowlists": []
    },
    {
      "id": "microsoft-teams-webhook",
      "description": "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.",
      "sourceRegex": "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
      "regex": "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "webhook.office.com",
        "webhookb2",
        "incomingwebhook"
      ],
      "allowlists": []
    },
    {
      "id": "netlify-access-token",
      "description": "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[nN][eE][tT][lL][iI][fF][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{40,46})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "netlify"
      ],
      "allowlists": []
    },
    {
      "id": "new-relic-browser-api-token",
      "description": "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([Nn][Rr][Jj][Ssſ]-[aAbBcCdDeEfF0-9]{19})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "nrjs-"
      ],
      "allowlists": []
    },
    {
      "id": "new-relic-insert-key",
      "description": "Discovered a New Relic insight insert key, compromising data injection into the platform.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([Nn][Rr][Ii][Ii]-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9-]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "nrii-"
      ],
      "allowlists": []
    },
    {
      "id": "new-relic-user-api-id",
      "description": "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "new-relic",
        "newrelic",
        "new_relic"
      ],
      "allowlists": []
    },
    {
      "id": "new-relic-user-api-key",
      "description": "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([Nn][Rr][Aa][KkK]-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{27})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "nrak"
      ],
      "allowlists": []
    },
    {
      "id": "notion-api-token",
      "description": "Notion API token",
      "sourceRegex": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "ntn_"
      ],
      "allowlists": []
    },
    {
      "id": "nytimes-access-token",
      "description": "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[nN][yY][tT][iI][mM][eE][sSſ]|[nN][eE][wW]-[yY][oO][rR][kKK]-[tT][iI][mM][eE][sSſ],|[nN][eE][wW][yY][oO][rR][kKK][tT][iI][mM][eE][sSſ])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "nytimes",
        "new-york-times",
        "newyorktimes"
      ],
      "allowlists": []
    },
    {
      "id": "octopus-deploy-api-key",
      "description": "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
      "sourceRegex": "\\b(API-[A-Z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(API-[A-Z0-9]{26})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "api-"
      ],
      "allowlists": []
    },
    {
      "id": "okta-access-token",
      "description": "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
      "sourceRegex": "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[\\w.-]{0,50}?(?:[A-Za-z0-9_ſK.-]{0,50}?(?:(?:[Oo]kta|OKTA))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}(00[\\w=\\x2d]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "okta"
      ],
      "allowlists": []
    },
    {
      "id": "openshift-user-token",
      "description": "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.",
      "sourceRegex": "\\b(sha256~[\\w-]{43})(?:[^\\w-]|\\z)",
      "regex": "\\b(sha256~[\\w-]{43})(?:[^\\w-]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "sha256~"
      ],
      "allowlists": []
    },
    {
      "id": "perplexity-api-key",
      "description": "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
      "sourceRegex": "\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$|\\b)",
      "regex": "\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S])|\\b)",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "pplx-"
      ],
      "allowlists": []
    },
    {
      "id": "plaid-api-token",
      "description": "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aA][cC][cC][eE][sSſ][sSſ]-(?:[sSſ][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "plaid"
      ],
      "allowlists": []
    },
    {
      "id": "plaid-client-id",
      "description": "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{24})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "plaid"
      ],
      "allowlists": []
    },
    {
      "id": "plaid-secret-key",
      "description": "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{30})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "plaid"
      ],
      "allowlists": []
    },
    {
      "id": "planetscale-api-token",
      "description": "Identified a PlanetScale API token, potentially compromising database management and operations.",
      "sourceRegex": "\\b(pscale_tkn_(?i)[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(pscale_tkn_[A-Za-z0-9_ſK=\\.-]{32,64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "pscale_tkn_"
      ],
      "allowlists": []
    },
    {
      "id": "planetscale-oauth-token",
      "description": "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
      "sourceRegex": "\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "pscale_oauth_"
      ],
      "allowlists": []
    },
    {
      "id": "planetscale-password",
      "description": "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
      "sourceRegex": "(?i)\\b(pscale_pw_(?i)[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b([pP][sSſ][cC][aA][lL][eE]_[pP][wW]_[A-Za-z0-9_ſK=\\.-]{32,64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "pscale_pw_"
      ],
      "allowlists": []
    },
    {
      "id": "postman-api-token",
      "description": "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
      "sourceRegex": "\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(PMAK-[aAbBcCdDeEfF0-9]{24}\\x2d[aAbBcCdDeEfF0-9]{34})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "pmak-"
      ],
      "allowlists": []
    },
    {
      "id": "prefect-api-token",
      "description": "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
      "sourceRegex": "\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "pnu_"
      ],
      "allowlists": []
    },
    {
      "id": "privateai-api-token",
      "description": "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
      "sourceRegex": "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[\\w.-]{0,50}?(?:[A-Za-z0-9_ſK.-]{0,50}?(?:[pP][rR][iI][vV][aA][tT][eE][_-]?[aA][iI])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "privateai",
        "private_ai",
        "private-ai"
      ],
      "allowlists": []
    },
    {
      "id": "pulumi-api-token",
      "description": "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
      "sourceRegex": "\\b(pul-[a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(pul-[a-f0-9]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "pul-"
      ],
      "allowlists": []
    },
    {
      "id": "pypi-upload-token",
      "description": "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
      "sourceRegex": "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
      "regex": "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "pypi-ageichlwas5vcmc"
      ],
      "allowlists": []
    },
    {
      "id": "rapidapi-access-token",
      "description": "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{50})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[rR][aA][pP][iI][dD][aA][pP][iI])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_-]{50})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "rapidapi"
      ],
      "allowlists": []
    },
    {
      "id": "readme-api-token",
      "description": "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
      "sourceRegex": "\\b(rdme_[a-z0-9]{70})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(rdme_[a-z0-9]{70})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "rdme_"
      ],
      "allowlists": []
    },
    {
      "id": "rubygems-api-token",
      "description": "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
      "sourceRegex": "\\b(rubygems_[a-f0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(rubygems_[a-f0-9]{48})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "rubygems_"
      ],
      "allowlists": []
    },
    {
      "id": "scalingo-api-token",
      "description": "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
      "sourceRegex": "\\b(tk-us-[\\w-]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(tk-us-[\\w-]{48})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "tk-us-"
      ],
      "allowlists": []
    },
    {
      "id": "sendbird-access-id",
      "description": "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[sSſ][eE][nN][dD][bB][iI][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "sendbird"
      ],
      "allowlists": []
    },
    {
      "id": "sendbird-access-token",
      "description": "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[sSſ][eE][nN][dD][bB][iI][rR][dD])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "sendbird"
      ],
      "allowlists": []
    },
    {
      "id": "sendgrid-api-token",
      "description": "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
      "sourceRegex": "\\b(SG\\.(?i)[a-z0-9=_\\-\\.]{66})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(SG\\.[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d\\.]{66})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "sg."
      ],
      "allowlists": []
    },
    {
      "id": "sendinblue-api-token",
      "description": "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
      "sourceRegex": "\\b(xkeysib-[a-f0-9]{64}\\-(?i)[a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(xkeysib-[a-f0-9]{64}\\x2d[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "xkeysib-"
      ],
      "allowlists": []
    },
    {
      "id": "sentry-access-token",
      "description": "Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[sSſ][eE][nN][tT][rR][yY])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sentry"
      ],
      "allowlists": []
    },
    {
      "id": "sentry-org-token",
      "description": "Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data.",
      "sourceRegex": "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\\z)",
      "regex": "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4.5,
      "keywords": [
        "sntrys_eyjpyxqio"
      ],
      "allowlists": []
    },
    {
      "id": "sentry-user-token",
      "description": "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.",
      "sourceRegex": "\\b(sntryu_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sntryu_[a-f0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "sntryu_"
      ],
      "allowlists": []
    },
    {
      "id": "settlemint-application-access-token",
      "description": "Found a Settlemint Application Access Token.",
      "sourceRegex": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sm_aat"
      ],
      "allowlists": []
    },
    {
      "id": "settlemint-personal-access-token",
      "description": "Found a Settlemint Personal Access Token.",
      "sourceRegex": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sm_pat"
      ],
      "allowlists": []
    },
    {
      "id": "settlemint-service-access-token",
      "description": "Found a Settlemint Service Access Token.",
      "sourceRegex": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sm_sat"
      ],
      "allowlists": []
    },
    {
      "id": "shippo-api-token",
      "description": "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
      "sourceRegex": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "shippo_"
      ],
      "allowlists": []
    },
    {
      "id": "shopify-access-token",
      "description": "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.",
      "sourceRegex": "shpat_[a-fA-F0-9]{32}",
      "regex": "shpat_[a-fA-F0-9]{32}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "shpat_"
      ],
      "allowlists": []
    },
    {
      "id": "shopify-custom-access-token",
      "description": "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
      "sourceRegex": "shpca_[a-fA-F0-9]{32}",
      "regex": "shpca_[a-fA-F0-9]{32}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "shpca_"
      ],
      "allowlists": []
    },
    {
      "id": "shopify-private-app-access-token",
      "description": "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.",
      "sourceRegex": "shppa_[a-fA-F0-9]{32}",
      "regex": "shppa_[a-fA-F0-9]{32}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "shppa_"
      ],
      "allowlists": []
    },
    {
      "id": "shopify-shared-secret",
      "description": "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
      "sourceRegex": "shpss_[a-fA-F0-9]{32}",
      "regex": "shpss_[a-fA-F0-9]{32}",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "shpss_"
      ],
      "allowlists": []
    },
    {
      "id": "sidekiq-secret",
      "description": "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[Bb][Uu][Nn][Dd][Ll][Ee]_[Ee][Nn][Tt][Ee][Rr][Pp][Rr][Ii][Ssſ][Ee]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ssſ][Yy][Ssſ]__[Cc][Oo][Mm]|[Bb][Uu][Nn][Dd][Ll][Ee]_[Gg][Ee][Mm][Ssſ]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ssſ][Yy][Ssſ]__[Cc][Oo][Mm])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfF0-9]{8}:[aAbBcCdDeEfF0-9]{8})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "bundle_enterprise__contribsys__com",
        "bundle_gems__contribsys__com"
      ],
      "allowlists": []
    },
    {
      "id": "sidekiq-sensitive-url",
      "description": "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.",
      "sourceRegex": "(?i)\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)",
      "regex": "\\b[hH][tT][tT][pP][sSſ]?://([aAbBcCdDeEfF0-9]{8}:[aAbBcCdDeEfF0-9]{8})@(?:[gG][eE][mM][sSſ][^\\n][cC][oO][nN][tT][rR][iI][bB][sSſ][yY][sSſ][^\\n][cC][oO][mM]|[eE][nN][tT][eE][rR][pP][rR][iI][sSſ][eE][^\\n][cC][oO][nN][tT][rR][iI][bB][sSſ][yY][sSſ][^\\n][cC][oO][mM])(?:[\\/|\\x23|\\?|:]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "gems.contribsys.com",
        "enterprise.contribsys.com"
      ],
      "allowlists": []
    },
    {
      "id": "snyk-api-token",
      "description": "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[sSſ][nN][yY][kKK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kKK][eE][yY]|[tT][oO][kKK][eE][nN]))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "snyk"
      ],
      "allowlists": []
    },
    {
      "id": "sonar-api-token",
      "description": "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[sSſ][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kKK][eE][nN]))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}((?:[sSſ][qQ][uU]_|[sSſ][qQ][pP]_|[sSſ][qQ][aA]_)?[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9=_\\x2d]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 2,
      "entropy": 0,
      "keywords": [
        "sonar"
      ],
      "allowlists": []
    },
    {
      "id": "sourcegraph-access-token",
      "description": "Sourcegraph is a code search and navigation engine.",
      "sourceRegex": "(?i)\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(\\b([sSſ][gG][pP]_(?:[aAbBcCdDeEfFAaBbCcDdEeFf0-9]{16}|[lL][oO][cC][aA][lL])_[aAbBcCdDeEfFAaBbCcDdEeFf0-9]{40}|[sSſ][gG][pP]_[aAbBcCdDeEfFAaBbCcDdEeFf0-9]{40}|[aAbBcCdDeEfFAaBbCcDdEeFf0-9]{40})\\b)(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sgp_",
        "sourcegraph"
      ],
      "allowlists": []
    },
    {
      "id": "square-access-token",
      "description": "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
      "sourceRegex": "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 2,
      "keywords": [
        "sq0atp-",
        "eaaa"
      ],
      "allowlists": []
    },
    {
      "id": "squarespace-access-token",
      "description": "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[sSſ][qQ][uU][aA][rR][eE][sSſ][pP][aA][cC][eE])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9aAbBcCdDeEfF]{8}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{4}-[0-9aAbBcCdDeEfF]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "squarespace"
      ],
      "allowlists": []
    },
    {
      "id": "sumologic-access-id",
      "description": "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
      "sourceRegex": "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[\\w.-]{0,50}?(?:[A-Za-z0-9_ſK.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sumo"
      ],
      "allowlists": []
    },
    {
      "id": "sumologic-access-token",
      "description": "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{64})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sumo"
      ],
      "allowlists": []
    },
    {
      "id": "telegram-bot-api-token",
      "description": "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9]{5,16}:(?:A)[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_\\x2d]{34})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "telegr"
      ],
      "allowlists": []
    },
    {
      "id": "travisci-access-token",
      "description": "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][rR][aA][vV][iI][sSſ])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{22})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "travis"
      ],
      "allowlists": []
    },
    {
      "id": "twilio-api-key",
      "description": "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
      "sourceRegex": "SK[0-9a-fA-F]{32}",
      "regex": "SK[0-9a-fA-F]{32}",
      "secretGroup": 0,
      "entropy": 3,
      "keywords": [
        "sk"
      ],
      "allowlists": []
    },
    {
      "id": "twitch-api-token",
      "description": "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][wW][iI][tT][cC][hH])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{30})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "twitch"
      ],
      "allowlists": []
    },
    {
      "id": "twitter-access-secret",
      "description": "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{45})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "twitter"
      ],
      "allowlists": []
    },
    {
      "id": "twitter-access-token",
      "description": "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([0-9]{15,25}-[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZAaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9]{20,40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "twitter"
      ],
      "allowlists": []
    },
    {
      "id": "twitter-api-key",
      "description": "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{25})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "twitter"
      ],
      "allowlists": []
    },
    {
      "id": "twitter-api-secret",
      "description": "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{50})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "twitter"
      ],
      "allowlists": []
    },
    {
      "id": "twitter-bearer-token",
      "description": "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([Aa]{22}[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZAaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9%]{80,100})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "twitter"
      ],
      "allowlists": []
    },
    {
      "id": "typeform-api-token",
      "description": "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([tT][fF][pP]_[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9\\x2d_\\.=]{59})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "tfp_"
      ],
      "allowlists": []
    },
    {
      "id": "vault-batch-token",
      "description": "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
      "sourceRegex": "\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 4,
      "keywords": [
        "hvb."
      ],
      "allowlists": []
    },
    {
      "id": "vault-service-token",
      "description": "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
      "sourceRegex": "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?i:[a-z0-9]{24})))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?:[aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{24})))(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 3.5,
      "keywords": [
        "hvs.",
        "s."
      ],
      "allowlists": [
        {
          "condition": "OR",
          "regexTarget": "secret",
          "regexes": [
            "s\\.[A-Za-z]{24}"
          ],
          "stopwords": [],
          "paths": []
        }
      ]
    },
    {
      "id": "yandex-access-token",
      "description": "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([tT]1\\.[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ_-]+[=]{0,2}\\.[AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ_-]{86}[=]{0,2})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "yandex"
      ],
      "allowlists": []
    },
    {
      "id": "yandex-api-key",
      "description": "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([Aa][Qq][Vv][Nn][AaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZzaAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9_\\x2d]{35,38})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "yandex"
      ],
      "allowlists": []
    },
    {
      "id": "yandex-aws-access-token",
      "description": "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([Yy][Cc][aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZAaBbCcDdEeFfGgHhIiJjKkKLlMmNnOoPpQqRrSsſTtUuVvWwXxYyZz0-9_\\x2d]{38})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "yandex"
      ],
      "allowlists": []
    },
    {
      "id": "zendesk-secret-key",
      "description": "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
      "sourceRegex": "(?i)[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "regex": "[A-Za-z0-9_ſK.-]{0,50}?(?:[zZ][eE][nN][dD][eE][sSſ][kKK])(?:[ \\tA-Za-z0-9_ſK.-]{0,20})[\\t\\n\\f\\r '\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\t\\n\\f\\r =]{0,5}([aAbBcCdDeEfFgGhHiIjJkKKlLmMnNoOpPqQrRsSſtTuUvVwWxXyYzZ0-9]{40})(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nNrR]|(?![\\s\\S]))",
      "secretGroup": 0,
      "entropy": 0,
      "keywords": [
        "zendesk"
      ],
      "allowlists": []
    }
  ]
});
})();
