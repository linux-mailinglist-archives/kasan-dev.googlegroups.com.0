Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAWFUKBAMGQEG7ILFUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E8E42333A46
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:42:10 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id f3sf7783052wrt.14
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:42:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372930; cv=pass;
        d=google.com; s=arc-20160816;
        b=sQKoDVtUswlbmQzj03WlEEBN/H2W+BvKsnwb/uI2ZSI5b9KhvgXlB26cxeDXZ0BIFX
         mrPYXGJH1BZKMrCo4poz67TRkwo+WeFoCCylmcReI+4RzlasVPMnrp4HuqjGvNxr5uDs
         CiFaUsn2usyPZwNqkNa9J1NB6opjH34b7r6ODPcifjWJ+sjb6uAijXl04mpUpB9vh4L7
         wDu6Tlw7VUXCOwxzZbG3y5T+2cYXxvSPiJQ3ityUn3TTjakZ122YxeCrt2IqtuWyH6+7
         zguYklUURyigy9MMWQimqYfuVfxWZGTdRJvF5QBK9qCfHB/tPZ0C1+W+Fz4WbBvl0+s+
         +V+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SczSbotupuFHPj8EL/4xXI1ipRf9290joX0UaWfo9iQ=;
        b=ty9rI8mAwYXI5E835Ypva92fi5I+raoZGtoZupxkWSh2kUL9r+HidrJliAIy491+IB
         LwWeaaeaZXKE/2R/tMXKBih9rD/N9xVb4ByYvOBD7DjyQjSds+hgol3zbLAGqVrXxm53
         scUQ/cZmyHo/q9QwVgQkfZfHk3JBlVzt/18Zwft5CHAHw35RnnrVrliaQD7QWZqyPI7x
         g0Cln9Ky6HAEajViwfF4B4JdVKpZBQ70vIxlI3SnCjIpK6mlh2kNUDnEUiyGxf875k6p
         dT3w1rVDWze/558t2qj2Kbeop57kN6R3jHaQHpHjL293JR51PjmGMqY/7s0sS9BaSpUD
         4P1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oT8UbYzH;
       spf=pass (google.com: domain of 3gajiyaukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gaJIYAUKCfAWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SczSbotupuFHPj8EL/4xXI1ipRf9290joX0UaWfo9iQ=;
        b=kx0kNOSnF88EqC8dTHqDWxyfAsAxznVZS+vFTTxVwpsVm+DqxVXO3K0dxCh3dU69+R
         Ap3Uoy+WzHarUWiaG4Dx+Nmi6sJ6rnUrcc2wQMxTo2byJE1MSSopvyIDDCR9DzApSAMN
         CufNXO3oKwB6ooymQqiFQLNMfQvZw0YNTVsaYwokR1KfmoYJ9soGBJ95/oF2Pu4wcCfj
         OYXedP8AUn8865usGSM5ar9aA/yrcZ4owS+auWH+glmIv17AoCTKfZv2Pl5gvJZzpqLb
         CRWUzCUScQxsSxmR6Hq8ce9nu9LJ0qIcNZa/Ay33Ih1WQlMEESwAAahmtDmMtiLcHFyP
         NzWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SczSbotupuFHPj8EL/4xXI1ipRf9290joX0UaWfo9iQ=;
        b=Mh1Hf1JQYJdFMkDUBOLbIgwCv0Zf1D9XXI8l6p1Z9+c8pNIcKw4FBJx9JlzwkDzQTi
         CGfNytKRjy1ER4kCGvh0N5q4qoatfeXhshQblwp+SqYHwRUOwln8CROpHBjzG6TA0oG+
         NQgYWa7rkzeOktSVz21wIAavDkGxc9AxHEt5etWAm/HjcKpEAGWn3YEuHelx22Pnwyh5
         IyAydxdZ83Bc7pHw5PoIlpuGpbno3HoNLkfIaXw5/qF7EFwor+zVXIUy0dkCPMAOK8pj
         QJJZRcVyJ2l0NxFvosOkfnOM+DOssx3K9Sd7sMRq7dCwS3YMDHjqvEh3iWWsli9PLQiy
         EWLQ==
X-Gm-Message-State: AOAM530/aXhg6eA11mzYOeioe8lleoU+8gJO4uDq4bD/Nkux+7ItOvMV
	f63DJMXJYYnfeUXYDsJEWVo=
X-Google-Smtp-Source: ABdhPJwu4YDKRtmnU41RFv99TSvgxpdG2/5G+ZVzHL7LbD2k6agjXDYVc3AH8nD3sapvZ15mktsKpA==
X-Received: by 2002:adf:8104:: with SMTP id 4mr2815725wrm.265.1615372930701;
        Wed, 10 Mar 2021 02:42:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:162d:: with SMTP id v13ls896498wrb.1.gmail; Wed, 10
 Mar 2021 02:42:09 -0800 (PST)
X-Received: by 2002:adf:ea47:: with SMTP id j7mr2734342wrn.377.1615372929743;
        Wed, 10 Mar 2021 02:42:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372929; cv=none;
        d=google.com; s=arc-20160816;
        b=hdTyplbB1GSK5Hm1VSLnHzZxd35/KhNQG88WbjbHCZ8y44+HXTa5HMZil1N30m8hEV
         hF+1pG1PD1CdKgQOL6tpm2pGohklH1Tqc1Pq2jPXEyRbza+uXHL5zOnGHkDAlKELTrBm
         cNdOQIXTKZdEPGiMy7V42MiNQz01jDNFzuP0/3dcKnlcwAqmklt2pOlPYKRI6PHtuzq2
         UxyyQ1/RotysyjTaOmkJ/5W4qjCYSkZJit4Hx1Y8yESF1k7+Ca231qyWpZkfLSNgVPRz
         pXcIlBzKTujxVxxb6Z9AMNTOf6ou5OFpYeaB9civpU8yekrbqilG9CKslAdwarAcPs3C
         GZBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7/IRp5vkLAkmWPwXwPAt2lcWrbp37U2bBtUBzeSgBmg=;
        b=h56Np3XskQhAYxs3bs/2xi+8mhhSWV4WqBzQbICnwJCSIqcoKTrrX1mBMWKrtyGxqj
         xDyWHvUotYSw2v5KVjRY/G66uni6kSAmsN1hCNu6hqTTVKIYkbBBjSNKGI9FjrzSaluw
         5yRf+3VpCCub43QcpRc/WT/LIFvIewQisJFQCOO+S7pXYQcz9lW0/K01JHT29qytul4X
         EvqtXTI0TAu4tI5iqUc639pvpk1BZSEkL7depqtot0pu50EUMZeVbh7heDp0S/X4QHxy
         X+cV1uNH0a54Ak7ZBb38kALvw5fnZOBIJFIO3ojHUlkpuGhNDQ6mhc5vNbdTozycsxzO
         ZgkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oT8UbYzH;
       spf=pass (google.com: domain of 3gajiyaukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gaJIYAUKCfAWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r11si662125wrm.1.2021.03.10.02.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:42:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gajiyaukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h5so7771503wrr.17
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:42:09 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:a1c:4c17:: with SMTP id z23mr2721408wmf.17.1615372929385;
 Wed, 10 Mar 2021 02:42:09 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:39 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-9-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for remove_on_exec
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oT8UbYzH;       spf=pass
 (google.com: domain of 3gajiyaukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gaJIYAUKCfAWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Add kselftest to test that remove_on_exec removes inherited events from
child tasks.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add patch to series.
---
 .../testing/selftests/perf_events/.gitignore  |   1 +
 tools/testing/selftests/perf_events/Makefile  |   2 +-
 .../selftests/perf_events/remove_on_exec.c    | 256 ++++++++++++++++++
 3 files changed, 258 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/perf_events/remove_on_exec.c

diff --git a/tools/testing/selftests/perf_events/.gitignore b/tools/testing/selftests/perf_events/.gitignore
index 4dc43e1bd79c..790c47001e77 100644
--- a/tools/testing/selftests/perf_events/.gitignore
+++ b/tools/testing/selftests/perf_events/.gitignore
@@ -1,2 +1,3 @@
 # SPDX-License-Identifier: GPL-2.0-only
 sigtrap_threads
+remove_on_exec
diff --git a/tools/testing/selftests/perf_events/Makefile b/tools/testing/selftests/perf_events/Makefile
index 973a2c39ca83..fcafa5f0d34c 100644
--- a/tools/testing/selftests/perf_events/Makefile
+++ b/tools/testing/selftests/perf_events/Makefile
@@ -2,5 +2,5 @@
 CFLAGS += -Wl,-no-as-needed -Wall -I../../../../usr/include
 LDFLAGS += -lpthread
 
-TEST_GEN_PROGS := sigtrap_threads
+TEST_GEN_PROGS := sigtrap_threads remove_on_exec
 include ../lib.mk
diff --git a/tools/testing/selftests/perf_events/remove_on_exec.c b/tools/testing/selftests/perf_events/remove_on_exec.c
new file mode 100644
index 000000000000..e176b3a74d55
--- /dev/null
+++ b/tools/testing/selftests/perf_events/remove_on_exec.c
@@ -0,0 +1,256 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test for remove_on_exec.
+ *
+ * Copyright (C) 2021, Google LLC.
+ */
+
+#define _GNU_SOURCE
+#include <sys/types.h>
+
+/* We need the latest siginfo from the kernel repo. */
+#include <asm/siginfo.h>
+#define __have_siginfo_t 1
+#define __have_sigval_t 1
+#define __have_sigevent_t 1
+
+#include <linux/perf_event.h>
+#include <pthread.h>
+#include <signal.h>
+#include <stdatomic.h>
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <sys/ioctl.h>
+#include <sys/syscall.h>
+#include <unistd.h>
+
+#include "../kselftest_harness.h"
+
+static volatile int signal_count;
+
+static struct perf_event_attr make_event_attr(void)
+{
+	struct perf_event_attr attr = {
+		.type		= PERF_TYPE_HARDWARE,
+		.size		= sizeof(attr),
+		.config		= PERF_COUNT_HW_INSTRUCTIONS,
+		.sample_period	= 1000,
+		.exclude_kernel = 1,
+		.exclude_hv	= 1,
+		.disabled	= 1,
+		.inherit	= 1,
+		/*
+		 * Children normally retain their inherited event on exec; with
+		 * remove_on_exec, we'll remove their event, but the parent and
+		 * any other non-exec'd children will keep their events.
+		 */
+		.remove_on_exec = 1,
+		.sigtrap	= 1,
+	};
+	return attr;
+}
+
+static void sigtrap_handler(int signum, siginfo_t *info, void *ucontext)
+{
+	if (info->si_code != TRAP_PERF) {
+		fprintf(stderr, "%s: unexpected si_code %d\n", __func__, info->si_code);
+		return;
+	}
+
+	signal_count++;
+}
+
+FIXTURE(remove_on_exec)
+{
+	struct sigaction oldact;
+	int fd;
+};
+
+FIXTURE_SETUP(remove_on_exec)
+{
+	struct perf_event_attr attr = make_event_attr();
+	struct sigaction action = {};
+
+	signal_count = 0;
+
+	/* Initialize sigtrap handler. */
+	action.sa_flags = SA_SIGINFO | SA_NODEFER;
+	action.sa_sigaction = sigtrap_handler;
+	sigemptyset(&action.sa_mask);
+	ASSERT_EQ(sigaction(SIGTRAP, &action, &self->oldact), 0);
+
+	/* Initialize perf event. */
+	self->fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
+	ASSERT_NE(self->fd, -1);
+}
+
+FIXTURE_TEARDOWN(remove_on_exec)
+{
+	close(self->fd);
+	sigaction(SIGTRAP, &self->oldact, NULL);
+}
+
+/* Verify event propagates to fork'd child. */
+TEST_F(remove_on_exec, fork_only)
+{
+	int status;
+	pid_t pid = fork();
+
+	if (pid == 0) {
+		ASSERT_EQ(signal_count, 0);
+		ASSERT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+		while (!signal_count);
+		_exit(42);
+	}
+
+	while (!signal_count); /* Child enables event. */
+	EXPECT_EQ(waitpid(pid, &status, 0), pid);
+	EXPECT_EQ(WEXITSTATUS(status), 42);
+}
+
+/*
+ * Verify that event does _not_ propagate to fork+exec'd child; event enabled
+ * after fork+exec.
+ */
+TEST_F(remove_on_exec, fork_exec_then_enable)
+{
+	pid_t pid_exec, pid_only_fork;
+	int pipefd[2];
+	int tmp;
+
+	/*
+	 * Non-exec child, to ensure exec does not affect inherited events of
+	 * other children.
+	 */
+	pid_only_fork = fork();
+	if (pid_only_fork == 0) {
+		/* Block until parent enables event. */
+		while (!signal_count);
+		_exit(42);
+	}
+
+	ASSERT_NE(pipe(pipefd), -1);
+	pid_exec = fork();
+	if (pid_exec == 0) {
+		ASSERT_NE(dup2(pipefd[1], STDOUT_FILENO), -1);
+		close(pipefd[0]);
+		execl("/proc/self/exe", "exec_child", NULL);
+		_exit((perror("exec failed"), 1));
+	}
+	close(pipefd[1]);
+
+	ASSERT_EQ(waitpid(pid_exec, &tmp, WNOHANG), 0); /* Child is running. */
+	/* Wait for exec'd child to start spinning. */
+	EXPECT_EQ(read(pipefd[0], &tmp, sizeof(int)), sizeof(int));
+	EXPECT_EQ(tmp, 42);
+	close(pipefd[0]);
+	/* Now we can enable the event, knowing the child is doing work. */
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	/* If the event propagated to the exec'd child, it will exit normally... */
+	usleep(100000); /* ... give time for event to trigger (in case of bug). */
+	EXPECT_EQ(waitpid(pid_exec, &tmp, WNOHANG), 0); /* Should still be running. */
+	EXPECT_EQ(kill(pid_exec, SIGKILL), 0);
+
+	/* Verify removal from child did not affect this task's event. */
+	tmp = signal_count;
+	while (signal_count == tmp); /* Should not hang! */
+	/* Nor should it have affected the first child. */
+	EXPECT_EQ(waitpid(pid_only_fork, &tmp, 0), pid_only_fork);
+	EXPECT_EQ(WEXITSTATUS(tmp), 42);
+}
+
+/*
+ * Verify that event does _not_ propagate to fork+exec'd child; event enabled
+ * before fork+exec.
+ */
+TEST_F(remove_on_exec, enable_then_fork_exec)
+{
+	pid_t pid_exec;
+	int tmp;
+
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+
+	pid_exec = fork();
+	if (pid_exec == 0) {
+		execl("/proc/self/exe", "exec_child", NULL);
+		_exit((perror("exec failed"), 1));
+	}
+
+	/*
+	 * The child may exit abnormally at any time if the event propagated and
+	 * a SIGTRAP is sent before the handler was set up.
+	 */
+	usleep(100000); /* ... give time for event to trigger (in case of bug). */
+	EXPECT_EQ(waitpid(pid_exec, &tmp, WNOHANG), 0); /* Should still be running. */
+	EXPECT_EQ(kill(pid_exec, SIGKILL), 0);
+
+	/* Verify removal from child did not affect this task's event. */
+	tmp = signal_count;
+	while (signal_count == tmp); /* Should not hang! */
+}
+
+TEST_F(remove_on_exec, exec_stress)
+{
+	pid_t pids[30];
+	int i, tmp;
+
+	for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
+		pids[i] = fork();
+		if (pids[i] == 0) {
+			execl("/proc/self/exe", "exec_child", NULL);
+			_exit((perror("exec failed"), 1));
+		}
+
+		/* Some forked with event disabled, rest with enabled. */
+		if (i > 10)
+			EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	}
+
+	usleep(100000); /* ... give time for event to trigger (in case of bug). */
+
+	for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
+		/* All children should still be running. */
+		EXPECT_EQ(waitpid(pids[i], &tmp, WNOHANG), 0);
+		EXPECT_EQ(kill(pids[i], SIGKILL), 0);
+	}
+
+	/* Verify event is still alive. */
+	tmp = signal_count;
+	while (signal_count == tmp);
+}
+
+/* For exec'd child. */
+static void exec_child(void)
+{
+	struct sigaction action = {};
+	const int val = 42;
+
+	/* Set up sigtrap handler in case we erroneously receive a trap. */
+	action.sa_flags = SA_SIGINFO | SA_NODEFER;
+	action.sa_sigaction = sigtrap_handler;
+	sigemptyset(&action.sa_mask);
+	if (sigaction(SIGTRAP, &action, NULL))
+		_exit((perror("sigaction failed"), 1));
+
+	/* Signal parent that we're starting to spin. */
+	if (write(STDOUT_FILENO, &val, sizeof(int)) == -1)
+		_exit((perror("write failed"), 1));
+
+	/* Should hang here until killed. */
+	while (!signal_count);
+}
+
+#define main test_main
+TEST_HARNESS_MAIN
+#undef main
+int main(int argc, char *argv[])
+{
+	if (!strcmp(argv[0], "exec_child")) {
+		exec_child();
+		return 1;
+	}
+
+	return test_main(argc, argv);
+}
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-9-elver%40google.com.
