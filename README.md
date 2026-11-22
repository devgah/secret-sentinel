# SecretSentinel

scanner de segredos em java 21+. varre uma pasta, encontra credenciais e retorna 1 quando acha algo.

<div style="background:#000;color:#00ff66;padding:16px;overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;line-height:1.4">
<pre>
  ____             _   _             _   _   ____  _____ ____  _____
 / ___|  ___ _ __ | |_(_)_   _____ | | | | / ___|| ____|  _ \| ____|
 \___ \ / _ \ '_ \| __| \ \ / / _ \| | | | \___ \|  _| | |_) |  _|
  ___) |  __/ |_) | |_| |\ V /  __/| |_| |  ___) | |___|  _ &lt;| |___
 |____/ \___| .__/ \__|_| \_/ \___| \___/  |____/|_____|_| \_\_____|
             |_|

root@secretsentinel:~$ java -jar secret-sentinel.jar --path demo-repo
arquivos analisados: 4
tempo de scan: 46 ms

achados: 11
CRITICAL .env:2        [AWS_ACCESS_KEY]    AKIA************8X2A
CRITICAL .env:4        [GITHUB_TOKEN]      ghp_************6789
HIGH     .env:6        [HARDCODED_SECRET]  Su************26
CRITICAL Config.java:6 [PRIVATE_KEY]       ----************----
MEDIUM   deploy.yml:6  [HIGH_ENTROPY]      aB3x************5mN1

criticos: 4 | altos: 5 | medios: 2
root@secretsentinel:~$ echo $?
1
</pre>
</div>

## uso

```
mvn clean package
java -jar target/secret-sentinel.jar --path .
java -jar target/secret-sentinel.jar --path . --format md --output relatorio.md
java -jar target/secret-sentinel.jar --path . --format none --entropy 4.2
java -jar target/secret-sentinel.jar --help
```

o `demo-repo/` tem credenciais falsas para testar sem usar dados reais.

## opcoes

| opcao | descricao | padrao |
| --- | --- | --- |
| `--path <diretorio>` | diretorio a verificar | obrigatorio |
| `--format <html\|md\|none>` | formato do relatorio | `html` |
| `--output <arquivo>` | caminho do relatorio | `secret-sentinel-report.<formato>` |
| `--entropy <valor>` | limite de entropia, de 0 a 16 | `4.5` |

## codigos de saida

| codigo | significado |
| --- | --- |
| `0` | nenhum segredo |
| `1` | segredos encontrados |
| `2` | erro de uso ou leitura |

## regras

AWS Access Key, chave privada PEM, token `ghp_` e `github_pat_`, JWT, chave `AIza`, atribuicoes hardcoded e entropia de Shannon acima de 4,5 bits em tokens com 20 ou mais caracteres.

ignora `.git`, `node_modules`, `target`, `build`, `.idea`, binarios, symlinks e linhas acima de 64 KB.

## seguranca

valores sao sempre mascarados; saida, HTML e Markdown sao sanitizados; symlinks nao sao seguidos; arquivos e leituras simultaneas tem limite; regex usam quantificadores possessivos contra ReDoS.

## teste

o projeto tem 39 testes JUnit 5. o CI compila, roda os testes e escaneia o proprio codigo-fonte.

## licenca

MIT. veja [LICENSE](LICENSE).
