Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNWD5SBAMGQEDV7H5WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B8CC5347717
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:42 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id r12sf1036154ljp.22
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585142; cv=pass;
        d=google.com; s=arc-20160816;
        b=q1zXM4tcATc5JO2lmeW/sp5st844HuRYvgKXFPYcIIuk4II8nC0xKTMgHccv0M+rRu
         6bMVjIpuVqH7VisxY35hVPtYa+QaeMeFPwtnQ+z8daWDaLrdFzEffTF6KIadDqK7Hf8y
         1o/UQXzEMEo85JV2ePUSAn8/Yo/kGNIm4PX+k71wwAauWlriY75Awy4ZXwiURzgs/nvP
         hFN4Xw2jCumP1y4X1WwHNMjCmsjtfclfUnZSQg9DDbfo8iypxY7I7k9hHL/VR4qyA2RN
         fVmf8Iqs7VN3+ot+dgFkO1LfFxSBpSq/djSyY/MqZ6nstKkuIcV7n98KjLvmCOzkfAUx
         6HHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=bARvidSZg7zCSrAkFjljBUM2NcIhsXszZ8toj06iXJ4=;
        b=kYv6L4jryp3PHJ6qRkTXmPMR/62YH0lwQgoZh1lzBgYRo3ZdkaoEDaZZQSIXyBcpUt
         PSc9gbFfRwZBYsNOJEgJc5mSVmlNrM0K5tqgxHw4doa68gbW7/MfzJeV2nJuV87eElvg
         Tn5yaiIlN7SWbZuCCs7AOFitnDs6uNpTBKy9JQXB67lXqU6qKBK7U6rCh5Nhte1oBPiN
         RIXVEEIxzBznUMdy7XggmMkJceygXsK6USXphZ8LyjLA2O4F/hPB+Cu8/P6zYHLkqBXP
         b+zQsQQYeacZ8zFmZypq1JRcmleQqzryDuIxl3/SMA2DyVZ3Gy8XlrwIKEdFUEnAEXOZ
         a3YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GvCabDdv;
       spf=pass (google.com: domain of 3tcfbyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tCFbYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bARvidSZg7zCSrAkFjljBUM2NcIhsXszZ8toj06iXJ4=;
        b=OmYwFRfFFHxSIdBBsQUuEH8zR1OuzBT9Z21zie75zHZSrWGKI8XAJ4LrJg0h/zmI4V
         VtsAU/4UttLhGTwWY0yBQtOb4D0fJNqDnArAxDDNyYvpLl5yiVwNKJWU48Ftcwyq9pv7
         0lAYSMw0YTLDNbN43en/62ijBmzjPtTb8SeQh7XLoSXe+OzQ7XdDEcYkdXBiKgYojczU
         FcLUhv0aI2MzX4xevuE0Ih1UZ4//rYdybyjZ2FDFriE+1CH8U1UgdUT/+R+31X3hhu34
         DVlObnVdhwB+/Jcl5KwMShKEEK788Sz7eGAPRT7TMRSZIPtzDBI0WUrvGPiE8cd69gzf
         N4mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bARvidSZg7zCSrAkFjljBUM2NcIhsXszZ8toj06iXJ4=;
        b=r1ReaHtKYhl2h0aJLGdMVEsvYzW6oIgTXgwJvOEkG7NQnVvUH1Y7SLg6BJoEa4fcJz
         ZoRQzy5lBwEbRHcjq4V7xC9aea7z6It+5kI2keNLHwbv/en44maQM/oPGk1U4+lAgrXd
         WtmmFZgdygBqi+S55l+uKQj4oYZvoIS0Gx/83KwxTHAUuFMKt7gj/L/YkoeYGaA2jIFZ
         QsSDl5Y/bkqCWVcStZH2lQ3OZMj+jkFugq27xitHZTYj7emsOqQy9ZaucWwVKb8pevVi
         D7Oftc9kiAUfMwoYpmWkKSVEBl+2XbniDUqlQbuBolyOyP5nTLtEGxhmW+yf3GjM1+LL
         hFdQ==
X-Gm-Message-State: AOAM53259PUr5RW+EDYLm8jIiKNHPxwdCHVcAyNk4efjjRmcx8WkNfhJ
	ZlTrzPd8xtQMljISr6sxbqM=
X-Google-Smtp-Source: ABdhPJx9huArj6Hr5D/AOR9/6jfHI70XxgUN9L5XVWR2w7s4f4y4uMFthzy2mDSxfA2YiVY7nDrKYQ==
X-Received: by 2002:a19:4911:: with SMTP id w17mr1601696lfa.361.1616585142313;
        Wed, 24 Mar 2021 04:25:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f8:: with SMTP id v24ls1324160lfo.2.gmail; Wed, 24 Mar
 2021 04:25:41 -0700 (PDT)
X-Received: by 2002:ac2:4883:: with SMTP id x3mr1636039lfc.419.1616585141118;
        Wed, 24 Mar 2021 04:25:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585141; cv=none;
        d=google.com; s=arc-20160816;
        b=cMaGSj5drC4ixor6d52I0CvUuPmd0g4L3qgm+GcEBjbxiY/1zvJRvuVjMJmOMtTJ+C
         u+YLqZA0Wgk5S8qZel94GwWB3V2x2o7hmADywSqPQCA26ValDX5QdX4oIxCN9pt9axIV
         ZxVFmspnmbgKKMs3gIEjHICp8xiZRaxHk06/fl/vet8OipRmzBPWgKoR0dJVe1+yqTjy
         n5EzG4YNDfwvYOzWp7t8xEQNQCgkcaORfCKEAENn3b+5YigmxdTeRb2ULD4cMRH6/cI2
         wr1i2cwUASqTNF1C1eN3X+3NskinpB+W7Px9mxH9Op9LgYj1loP839x7pHq4enyI39JL
         VTLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=fK7o5DleNnJqQibEJC4DcBiUyuf/i/piGlRFLNZN3Fs=;
        b=dRzO6JsrSGz0VE+ahMYkccXdLdGT/sZpyyS8A2IWGEOK8tVLfIXs2lUfnI5qYY1i8R
         Kx1rrrxz5UH4noU7OT7Q6XvZG1SSDKV1haBB3LKaE/qVoV9VhhK72qkmrwcnnX9/yBva
         hypW382SFMSQMhejCD+UtalqDxwQt0pn8U5bmWDbsOCthINkdyKEeGLvjppFok/Ym5gB
         RSxE4DPK58OLkP79TkEYbuESkyvo48Ifk1JbjB9uWSg2fhVb6vhlxWTbb1nRdV+t40MD
         hFki79rDuHa1l8RuHSuW4WmtTjv6gyWgS8wlkcS5eTdWEUNVCovycT3htScTn9nXQBWo
         z5fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GvCabDdv;
       spf=pass (google.com: domain of 3tcfbyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tCFbYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v3si90314lfd.4.2021.03.24.04.25.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tcfbyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id a63so306463wmd.8
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:41 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a7b:c24e:: with SMTP id b14mr2415183wmj.73.1616585140432;
 Wed, 24 Mar 2021 04:25:40 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:25:01 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-10-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 09/11] selftests/perf_events: Add kselftest for remove_on_exec
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
 header.i=@google.com header.s=20161025 header.b=GvCabDdv;       spf=pass
 (google.com: domain of 3tcfbyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tCFbYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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
v3:
* Fix for latest libc signal.h.

v2:
* Add patch to series.
---
 .../testing/selftests/perf_events/.gitignore  |   1 +
 tools/testing/selftests/perf_events/Makefile  |   2 +-
 .../selftests/perf_events/remove_on_exec.c    | 260 ++++++++++++++++++
 3 files changed, 262 insertions(+), 1 deletion(-)
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
index 000000000000..5814611a1dc7
--- /dev/null
+++ b/tools/testing/selftests/perf_events/remove_on_exec.c
@@ -0,0 +1,260 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test for remove_on_exec.
+ *
+ * Copyright (C) 2021, Google LLC.
+ */
+
+#define _GNU_SOURCE
+
+/* We need the latest siginfo from the kernel repo. */
+#include <sys/types.h>
+#include <asm/siginfo.h>
+#define __have_siginfo_t 1
+#define __have_sigval_t 1
+#define __have_sigevent_t 1
+#define __siginfo_t_defined
+#define __sigval_t_defined
+#define __sigevent_t_defined
+#define _BITS_SIGINFO_CONSTS_H 1
+#define _BITS_SIGEVENT_CONSTS_H 1
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <linux/perf_event.h>
+#include <pthread.h>
+#include <signal.h>
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
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-10-elver%40google.com.
