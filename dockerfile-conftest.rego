package main

# ENV değişkenlerinde gizli bilgileri saklamayın
secrets_env = [
    "passwd",
    "password",
    "pass",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
    "tkn"
]

deny[msg] {    
    input[i].Cmd == "env"
    val := input[i].Value
    contains(lower(val), secrets_env[_])
    msg = sprintf("Satır %d: ENV anahtarında potansiyel bir gizli bilgi bulundu: %s", [i, val])
}

# Yalnızca güvenilir temel imajlar kullanın
deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value
    val_split := split(val, "/")
    count(val_split) > 1
    msg = sprintf("Satır %d: Güvenilir bir temel imaj kullanın", [i])
}

# 'latest' etiketini temel imajlar için kullanmayın
deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value
    val_split := split(val, ":")
    length(val_split) == 2
    contains(lower(val_split[1]), "latest")
    msg = sprintf("Satır %d: Temel imajlar için 'latest' etiketini kullanmayın", [i])
}

# curl bashing'den kaçının
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(val), -1)
    count(matches) > 0
    msg = sprintf("Satır %d: curl bashing'den kaçının", [i])
}

# Sistem paketlerini güncellemeyin
warn[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    matches := regex.match(".*?(apk|yum|dnf|apt|pip).+?(install|[dist-|check-|group]?up[grade|date]).*", lower(val))
    matches
    msg = sprintf("Satır %d: Sistem paketlerinizi güncellemeyin: %s", [i, val])
}

# ADD komutunu mümkünse kullanmayın
deny[msg] {
    input[i].Cmd == "add"
    msg = sprintf("Satır %d: ADD yerine COPY kullanın", [i])
}

# Herhangi bir kullanıcı...
any_user {
    input[i].Cmd == "user"
}

deny[msg] {
    not any_user
    msg = "Root olarak çalışmayın, USER komutunu kullanın"
}

# ... ama root olmamalı
forbidden_users = [
    "root",
    "toor",
    "0"
]

deny[msg] {
    input[i].Cmd == "user"
    users := [name | name := input[i].Value]
    lastuser := users[count(users)-1]
    contains(lower(lastuser), forbidden_users[_])
    msg = sprintf("Satır %d: Son USER direktifi (USER %s) yasaklı", [i, lastuser])
}

# sudo kullanmayın
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg = sprintf("Satır %d: 'sudo' komutunu kullanmayın", [i])
}

# Çok aşamalı derlemeler kullanın
default multi_stage = true
multi_stage = true {
    input[i].Cmd == "copy"
    val := concat(" ", input[i].Flags)
    contains(lower(val), "--from=")
}
deny[msg] {
    not multi_stage
    msg = sprintf("COPY kullanıyorsunuz, ancak çok aşamalı derlemeler kullanmıyor gibi görünüyorsunuz...", [])
}
