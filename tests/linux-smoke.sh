#!/bin/sh
# Only run inside the disposable test image, with its own PID namespace and log.
set -eu
test -f /.dockerenv || { echo "Refusing to provision test users outside Docker" >&2; exit 1; }
bin=/usr/local/sbin/agent-smith
useradd --uid 1100 --create-home reviewer
install -D -m 0600 /src/examples/policy.json /etc/agent-smith/policy.json
cd /home/reviewer
runuser -u reviewer -- git init -q --bare remote.git
runuser -u reviewer -- git init -q work
runuser -u reviewer -- git -C work -c user.name=Reviewer -c user.email=reviewer@example.invalid commit -qm baseline --allow-empty
runuser -u reviewer -- git -C work push -q ../remote.git HEAD:refs/heads/control
control=$(runuser -u reviewer -- git --git-dir=remote.git rev-parse refs/heads/control)

cd work
"$bin" run --user reviewer --profile review -- /usr/bin/git diff --exit-code
# Use a real child of a shell, not just direct execution by the supervisor.
code=0
"$bin" run --user reviewer --profile review -- /bin/sh -c \
  '/usr/bin/git -C /home/reviewer/work push ../remote.git HEAD:refs/heads/forbidden; rc=$?; exit "$rc"' || code=$?
test "$code" -eq 137 || { echo "Expected git to die from SIGKILL, got $code" >&2; exit 1; }
test "$(runuser -u reviewer -- git --git-dir=../remote.git for-each-ref --format='%(refname) %(objectname)')" = "refs/heads/control $control"
grep -q '"rule":"review-no-push"' /var/log/agent-smith.jsonl
echo "OK: review diff succeeded, nested push was killed, remote refs unchanged."
